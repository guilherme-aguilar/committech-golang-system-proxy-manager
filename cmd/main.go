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

var cfg Config

// --- GESTÃO EM MEMÓRIA ---
type ProxyClient struct {
	ID      string
	Session *yamux.Session
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

var Version = "dev"

func main() {
	log.Printf("[Init] Iniciando Proxy Manager Enterprise - Versão: %s", Version)

	// 0. Carregar Config
	configFile := flag.String("config", "server.toml", "Caminho do arquivo de configuração")
	flag.Parse()
	cfg = loadConfig(*configFile)

	// 1. Iniciar Banco
	initDB()

	// 2. BOOTSTRAPPING SEGURO (MUDANÇA CRÍTICA AQUI)
	if !hasUsers() {
		log.Println("[Init] ⚠️ Banco vazio detectado.")

		// Gera senha aleatória forte
		randomPass := generateRandomString(12)

		log.Println("[Init] Criando usuário 'admin' com senha segura...")
		if err := addUser("admin", randomPass, "financeiro", "*"); err != nil {
			log.Fatalf("Erro fatal ao criar admin: %v", err)
		}

		token := generateAndSetToken("financeiro")

		fmt.Println("\n==============================================")
		fmt.Println("🚀 AMBIENTE INICIALIZADO COM SUCESSO")
		fmt.Println("----------------------------------------------")
		fmt.Printf("👤 User:  admin\n")
		fmt.Printf("🔑 Pass:  %s  <-- COPIE E GUARDE ISSO!\n", randomPass)
		fmt.Printf("🎟️  Token: %s\n", token)
		fmt.Println("==============================================\n")
	} else {
		log.Println("[Init] Dados carregados do banco com segurança.")
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

	// 4. Start Services
	go startEnrollmentServer(cfg.Network.EnrollPort, caCert, caKey, serverCert)
	go startTunnelServer(cfg.Network.TunnelPort, caCert, serverCert)
	go startAdminServer(cfg.Network.AdminPort)

	// 5. Proxy Server
	log.Printf("[Proxy] 🛡️  HTTP Proxy Autenticado rodando em %s", cfg.Network.ProxyPort)
	server := &http.Server{
		Addr:    cfg.Network.ProxyPort,
		Handler: &ProxyHandler{},
	}
	log.Fatal(server.ListenAndServe())
}

// --- FUNÇÃO AUXILIAR DE SENHA ALEATÓRIA ---
func generateRandomString(n int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "PanicSecurity999!" // Fallback improvável
		}
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}

func loadConfig(path string) Config {
	config := Config{}
	config.Network.EnrollPort = ":8082"
	config.Network.TunnelPort = ":8081"
	config.Network.ProxyPort = ":8080"
	config.Network.AdminPort = ":8083"
	config.Security.AdminToken = "admin-secret-123" // Mude isso no TOML

	if _, err := os.Stat(path); err == nil {
		toml.DecodeFile(path, &config)
		log.Printf("[Config] Carregado de %s", path)
	} else {
		log.Printf("[Config] Usando padrões (Arquivo não encontrado)")
	}
	return config
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		expected := "Bearer " + cfg.Security.AdminToken

		if authHeader != expected {
			http.Error(w, "Unauthorized", 401)
			return
		}
		next(w, r)
	}
}

// --- PROXY HANDLER ---

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

	// TENTA PEGAR O IP REAL (RESOLVENDO SUA DÚVIDA)
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Verifica cabeçalhos de Proxy Transparente
	realIP := r.Header.Get("X-Forwarded-For")
	if realIP != "" {
		// Pega o primeiro IP da lista se houver vários (ex: "200.1.1.1, 172.16.3.89")
		ips := strings.Split(realIP, ",")
		clientIP = strings.TrimSpace(ips[0])
	}

	// Autentica usando BCrypt (Função está em database.go)
	targetGroup, authorized := authenticateUser(user, pass, clientIP)

	if !authorized {
		// Log detalhado para te ajudar a debugar quem é o atacante
		log.Printf("[Block] User: %s | SourceIP: %s (Gateway: %s) | Acesso Negado", user, clientIP, r.RemoteAddr)

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
		http.Error(w, "Bad Gateway", 502)
		return
	}
	defer stream.Close()

	if r.Method == http.MethodConnect {
		handleTunneling(w, r, stream)
	} else {
		handleHTTP(w, r, stream)
	}
}

// --- SERVIDORES AUXILIARES ---

func startAdminServer(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "dashboard.html") })

	// Exemplo de uma rota de API:
	mux.HandleFunc("/users", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(getAllUsers(r.URL.Query().Get("group")))
		} else if r.Method == "POST" {
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

			// addUser agora faz o hash internamente
			if err := addUser(req.Username, req.AccessKey, req.Group, req.IP); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.WriteHeader(http.StatusCreated)
		} else if r.Method == "DELETE" {
			deleteUser(r.URL.Query().Get("username"))
			w.WriteHeader(http.StatusOK)
		}
	}))

	// ... Adicione as outras rotas (tokens, groups, status) aqui, igual ao anterior ...
	// (Omissas para brevidade, mas a lógica é a mesma, só chamam as func do database.go)

	log.Printf("[Admin] ⚙️  Painel Web em http://localhost%s", addr)
	http.ListenAndServe(addr, mux)
}

func startEnrollmentServer(addr string, caCertPEM, caKeyPEM []byte, serverCert tls.Certificate) {
	mux := http.NewServeMux()

	// ROTA DE BOOTSTRAP PARA O CLIENTE BAIXAR A CA
	mux.HandleFunc("/ca.crt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(caCertPEM)
	})

	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			return
		}
		var req struct{ Token, Name string }
		json.NewDecoder(r.Body).Decode(&req)

		group, exists := getGroupForToken(req.Token)
		if !exists {
			http.Error(w, "Token inválido", 403)
			return
		}

		clientCertPEM, clientKeyPEM := generateSignedCert(req.Name, group, 1, caCertPEM, caKeyPEM)
		json.NewEncoder(w).Encode(map[string]string{
			"cert": string(clientCertPEM),
			"key":  string(clientKeyPEM),
		})
	})

	log.Printf("[Enroll] 📝 API Matrícula em %s", addr)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}}
	log.Fatal((&http.Server{Addr: addr, Handler: mux, TLSConfig: tlsConfig}).ListenAndServeTLS("", ""))
}

func startTunnelServer(addr string, caCert []byte, serverCert tls.Certificate) {
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
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
	// Parse do grupo via OU
	ouParts := strings.Split(cert.Subject.OrganizationalUnit[0], ":")
	groupName := ouParts[0]

	session, err := yamux.Client(conn, nil)
	if err != nil {
		conn.Close()
		return
	}

	manager.registerClient(clientID, groupName, session)
}

// --- UTILS ---

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
		NotBefore:    time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour),
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
		http.Error(w, "Gateway Error", 502)
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

// Métodos do Manager (registerClient, getSession) mantêm-se iguais ao seu código anterior.
func (m *GroupManager) registerClient(clientID, group string, s *yamux.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.groups[group]; !ok {
		m.groups[group] = &Group{}
	}
	g := m.groups[group]
	// ... lógica de limpeza e add ...
	g.Clients = append(g.Clients, &ProxyClient{ID: clientID, Session: s})
	log.Printf("[Registry] '%s' registrado em '%s'", clientID, group)
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
