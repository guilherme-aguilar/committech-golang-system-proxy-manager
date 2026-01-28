package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/hashicorp/yamux"
)

// --- ESTRUTURA DE CONFIGURAÇÃO (TOML) ---
type Config struct {
	Network struct {
		EnrollPort string `toml:"enroll_port"`
		TunnelPort string `toml:"tunnel_port"`
		ProxyPort  string `toml:"proxy_port"`
		AdminPort  string `toml:"admin_port"`
	} `toml:"network"`
	Security struct {
		AdminToken string `toml:"admin_token"`
	} `toml:"security"`
}

// Variável Global de Configuração
var cfg Config

// --- ESTRUTURAS DE GESTÃO EM MEMÓRIA ---
type ProxyClient struct {
	ID      string         // Nome Único
	Session *yamux.Session // A Conexão
}

type Group struct {
	Clients []*ProxyClient
	Counter uint64
}

type GroupManager struct {
	mu     sync.RWMutex
	groups map[string]*Group
}

var manager = &GroupManager{
	groups: make(map[string]*Group),
}

var (
	// Essa variável será sobrescrita pelo script de build!
	Version = "dev"
	// ... manager, cfg etc
)

func main() {

	// Mostra a versão no log ao iniciar
	log.Printf("[Init] Iniciando Proxy Manager Enterprise - Versão: %s", Version)

	// 0. Carregar Configurações
	configFile := flag.String("config", "server.toml", "Caminho do arquivo de configuração")
	flag.Parse()
	cfg = loadConfig(*configFile)

	log.Printf("[Config] Admin Token: %s", cfg.Security.AdminToken) // Log de debug (remover em prod)

	// 1. Iniciar Banco de Dados
	initDB()

	// 2. BOOTSTRAPPING INTELIGENTE
	if !hasUsers() {
		log.Println("[Init] Banco vazio. Criando ambiente padrão...")
		addUser("admin", "123456", "financeiro", "*")
		token := generateAndSetToken("financeiro")
		log.Printf("[Init] Token gerado para 'financeiro': %s", token)
	} else {
		log.Println("[Init] Dados carregados do banco com sucesso.")
	}

	// 3. Carregar Certificados
	caCert, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		log.Fatal("Erro: certs/ca.crt não encontrado")
	}

	caKey, err := os.ReadFile("certs/ca.key")
	if err != nil {
		log.Fatal("Erro: certs/ca.key não encontrado")
	}

	serverCert, err := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")
	if err != nil {
		log.Fatal("Erro: certs/server.* não encontrado")
	}

	// 4. Iniciar Serviços (Usando portas do Config)
	go startEnrollmentServer(cfg.Network.EnrollPort, caCert, caKey, serverCert)
	go startTunnelServer(cfg.Network.TunnelPort, caCert, serverCert)
	go startAdminServer(cfg.Network.AdminPort)

	// 5. Iniciar Proxy Principal
	log.Printf("[Proxy] 🛡️  HTTP Proxy Autenticado rodando em %s", cfg.Network.ProxyPort)
	server := &http.Server{
		Addr:    cfg.Network.ProxyPort,
		Handler: &ProxyHandler{},
	}
	log.Fatal(server.ListenAndServe())
}

// --- FUNÇÃO PARA CARREGAR CONFIG ---
func loadConfig(path string) Config {
	// Valores Padrão (caso o arquivo não exista ou falte campos)
	config := Config{}
	config.Network.EnrollPort = ":8082"
	config.Network.TunnelPort = ":8081"
	config.Network.ProxyPort = ":8080"
	config.Network.AdminPort = ":8083"
	config.Security.AdminToken = "admin-secret-123"

	if _, err := os.Stat(path); err == nil {
		if _, err := toml.DecodeFile(path, &config); err != nil {
			log.Printf("[Config] Erro ao ler %s: %v. Usando padrões.", path, err)
		} else {
			log.Printf("[Config] Carregado de %s", path)
		}
	} else {
		log.Printf("[Config] Arquivo %s não encontrado. Usando padrões.", path)
	}
	return config
}

// =========================================================================
// 1. MIDDLEWARE: AUTH + ANTI-CACHE
// =========================================================================

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		authHeader := r.Header.Get("Authorization")
		// Agora usa a variável global cfg
		expected := "Bearer " + cfg.Security.AdminToken

		if authHeader != expected {
			http.Error(w, "Unauthorized: Login Required", 401)
			return
		}

		next(w, r)
	}
}

// =========================================================================
// 2. PROXY HANDLER (CORE)
// =========================================================================

type ProxyHandler struct{}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Access"`)
		http.Error(w, "Authentication Required", 407)
		return
	}

	user, pass, ok := parseBasicAuth(authHeader)
	if !ok {
		http.Error(w, "Invalid Auth Format", 400)
		return
	}

	hostIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	targetGroup, authorized := authenticateUser(user, pass, hostIP)

	if !authorized {
		log.Printf("[Block] User: %s | IP: %s | Acesso Negado", user, hostIP)
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Access"`)
		http.Error(w, "Forbidden", 403)
		return
	}

	session := manager.getSession(targetGroup)
	if session == nil {
		http.Error(w, fmt.Sprintf("Nenhum proxy online no grupo: %s", targetGroup), 503)
		return
	}

	stream, err := session.Open()
	if err != nil {
		http.Error(w, "Bad Gateway (Tunnel Error)", 502)
		return
	}
	defer stream.Close()

	if r.Method == http.MethodConnect {
		handleTunneling(w, r, stream)
	} else {
		handleHTTP(w, r, stream)
	}
}

// =========================================================================
// 3. API ADMIN
// =========================================================================

func startAdminServer(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "dashboard.html") })

	mux.HandleFunc("/groups", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(getAllGroups())
			return
		}
		if r.Method == "POST" {
			var req struct{ Name string }
			json.NewDecoder(r.Body).Decode(&req)
			createGroup(req.Name)
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method == "DELETE" {
			group := r.URL.Query().Get("name")
			deleteGroup(group)
			manager.forceDisconnectGroup(group)
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == "PUT" {
			var req struct {
				Name   string
				Status string
			}
			json.NewDecoder(r.Body).Decode(&req)
			toggleGroupStatus(req.Name, req.Status)
			if req.Status == "inactive" {
				manager.forceDisconnectGroup(req.Name)
			}
			w.WriteHeader(http.StatusOK)
		}
	}))

	mux.HandleFunc("/connections", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			group := r.URL.Query().Get("group")
			id := r.URL.Query().Get("id")
			if manager.disconnectClient(group, id) {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}))

	mux.HandleFunc("/status", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		filter := r.URL.Query().Get("group")
		manager.mu.RLock()
		defer manager.mu.RUnlock()
		type ClientData struct {
			ID   string `json:"id"`
			Addr string `json:"addr"`
		}
		report := make(map[string][]ClientData)
		for groupName, group := range manager.groups {
			if filter != "" && filter != "all" && groupName != filter {
				continue
			}
			var active []ClientData
			for _, c := range group.Clients {
				if !c.Session.IsClosed() {
					active = append(active, ClientData{ID: c.ID, Addr: c.Session.RemoteAddr().String()})
				}
			}
			report[groupName] = active
		}
		json.NewEncoder(w).Encode(report)
	}))

	mux.HandleFunc("/proxy-tokens", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(getAllTokens(r.URL.Query().Get("group")))
			return
		}
		if r.Method == "POST" {
			var req struct{ Group string }
			json.NewDecoder(r.Body).Decode(&req)
			newToken := generateAndSetToken(req.Group)
			manager.forceDisconnectGroup(req.Group)
			json.NewEncoder(w).Encode(map[string]string{"token": newToken})
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method == "DELETE" {
			deleteToken(r.URL.Query().Get("token"))
			w.WriteHeader(http.StatusOK)
		}
	}))

	mux.HandleFunc("/users", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(getAllUsers(r.URL.Query().Get("group")))
			return
		}
		if r.Method == "POST" {
			var req struct {
				Username  string
				AccessKey string
				Group     string
				IP        string
			}
			json.NewDecoder(r.Body).Decode(&req)
			if req.IP == "" {
				req.IP = "*"
			}
			addUser(req.Username, req.AccessKey, req.Group, req.IP)
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method == "DELETE" {
			deleteUser(r.URL.Query().Get("username"))
			w.WriteHeader(http.StatusOK)
		}
	}))

	log.Printf("[Admin] ⚙️  Painel Web em http://localhost%s", addr)
	http.ListenAndServe(addr, mux)
}

// =========================================================================
// 4. SERVIDORES AUXILIARES
// =========================================================================

func startEnrollmentServer(addr string, caCertPEM, caKeyPEM []byte, serverCert tls.Certificate) {
	mux := http.NewServeMux()
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			return
		}
		var req struct {
			Token string
			Name  string
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Name == "" {
			http.Error(w, "Nome obrigatório", 400)
			return
		}
		group, exists := getGroupForToken(req.Token)
		if !exists {
			http.Error(w, "Token inválido", 403)
			return
		}
		currentVersion := getGroupVersion(group)
		clientCertPEM, clientKeyPEM := generateSignedCert(req.Name, group, currentVersion, caCertPEM, caKeyPEM)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"cert": string(clientCertPEM), "key": string(clientKeyPEM), "group": group})
	})
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}}
	log.Printf("[Enroll] 📝 API Matrícula em %s", addr)
	log.Fatal((&http.Server{Addr: addr, Handler: mux, TLSConfig: tlsConfig}).ListenAndServeTLS("", ""))
}

func startTunnelServer(addr string, caCert []byte, serverCert tls.Certificate) {
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)
	config := &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: caPool, ClientAuth: tls.RequireAndVerifyClientCert}
	ln, err := tls.Listen("tcp", addr, config)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("[Tunnel] 🔒 mTLS Listener em %s", addr)
	for {
		conn, err := ln.Accept()
		if err == nil {
			go handleNewTunnelConnection(conn)
		}
	}
}

func handleNewTunnelConnection(conn net.Conn) {
	tlsConn := conn.(*tls.Conn)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		conn.Close()
		return
	}
	cert := state.PeerCertificates[0]
	clientID := cert.Subject.CommonName
	ouParts := strings.Split(cert.Subject.OrganizationalUnit[0], ":")
	if len(ouParts) != 2 {
		log.Printf("[Block] ⛔ Certificado inválido: %s", clientID)
		conn.Close()
		return
	}
	groupName := ouParts[0]
	var certVersion int
	fmt.Sscanf(ouParts[1], "%d", &certVersion)
	if !isGroupValidStrict(groupName, certVersion) {
		log.Printf("[Block] ⛔ Proxy '%s' (v%d) rejeitada. Grupo '%s' exige v%d.", clientID, certVersion, groupName, getGroupVersion(groupName))
		conn.Close()
		return
	}
	session, err := yamux.Client(conn, nil)
	if err != nil {
		conn.Close()
		return
	}
	manager.registerClient(clientID, groupName, session)
}

// =========================================================================
// 5. GESTÃO DE GRUPOS & MEMÓRIA
// =========================================================================

func (m *GroupManager) registerClient(clientID, group string, s *yamux.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.groups[group]; !ok {
		m.groups[group] = &Group{}
	}
	g := m.groups[group]
	var activeClients []*ProxyClient
	for _, client := range g.Clients {
		if client.ID == clientID {
			log.Printf("[Conflict] ⚠️ Derrubando sessão antiga de '%s'", clientID)
			client.Session.Close()
		} else if client.Session.IsClosed() {
			continue
		} else {
			activeClients = append(activeClients, client)
		}
	}
	activeClients = append(activeClients, &ProxyClient{ID: clientID, Session: s})
	g.Clients = activeClients
	log.Printf("[Registry] '%s' registrado em '%s' (Total: %d)", clientID, group, len(g.Clients))
}

func (m *GroupManager) forceDisconnectGroup(groupName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g, ok := m.groups[groupName]; ok {
		log.Printf("[Admin] ✂️  Cortando %d conexões do grupo: %s", len(g.Clients), groupName)
		for _, client := range g.Clients {
			client.Session.Close()
		}
		delete(m.groups, groupName)
	}
}

func (m *GroupManager) disconnectClient(groupName, clientID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[groupName]
	if !ok {
		return false
	}
	found := false
	var remaining []*ProxyClient
	for _, client := range g.Clients {
		if client.ID == clientID {
			client.Session.Close()
			found = true
			log.Printf("[Admin] 👢 Proxy expulsa: %s", clientID)
		} else if !client.Session.IsClosed() {
			remaining = append(remaining, client)
		}
	}
	g.Clients = remaining
	return found
}

func (m *GroupManager) getSession(group string) *yamux.Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	g, ok := m.groups[group]
	if !ok || len(g.Clients) == 0 {
		return nil
	}
	idx := atomic.AddUint64(&g.Counter, 1) % uint64(len(g.Clients))
	return g.Clients[idx].Session
}

func parseBasicAuth(header string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

func generateSignedCert(name, group string, version int, caCertPEM, caKeyPEM []byte) ([]byte, []byte) {
	caKeyPair, _ := tls.X509KeyPair(caCertPEM, caKeyPEM)
	caCert, _ := x509.ParseCertificate(caKeyPair.Certificate[0])
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	groupOU := fmt.Sprintf("%s:%d", group, version)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name, OrganizationalUnit: []string{groupOU}},
		NotBefore:    time.Now(), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, caCert, &priv.PublicKey, caKeyPair.PrivateKey)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
}

func handleTunneling(w http.ResponseWriter, r *http.Request, stream net.Conn) {
	fmt.Fprintf(stream, "CONNECT %s HTTP/1.1\r\n\r\n", r.Host)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go io.Copy(stream, clientConn)
	io.Copy(clientConn, stream)
}

func handleHTTP(w http.ResponseWriter, r *http.Request, stream net.Conn) {
	r.Write(stream)
	resp, err := http.ReadResponse(bufio.NewReader(stream), r)
	if err != nil {
		http.Error(w, "Error reading response", 502)
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
