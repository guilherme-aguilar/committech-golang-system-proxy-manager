package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"proxy-manager/internal/config"
	"proxy-manager/internal/database"
	"proxy-manager/internal/manager"
)

// --- SISTEMA DE PRISÃO (JAIL) ---
var (
	jailMutex   sync.RWMutex
	bannedIPs   = make(map[string]time.Time)
	ipLastSeen  = make(map[string]time.Time)
	cleanupTime = time.Now()
)

func checkAndBan(ip string) (banned bool) {
	jailMutex.Lock()
	defer jailMutex.Unlock()

	now := time.Now()

	// 1. Limpeza automática
	if time.Since(cleanupTime) > 10*time.Minute {
		for k, v := range bannedIPs {
			if now.After(v) {
				delete(bannedIPs, k)
			}
		}
		ipLastSeen = make(map[string]time.Time)
		cleanupTime = now
	}

	// 2. Verifica Banimento
	if expireTime, isBanned := bannedIPs[ip]; isBanned {
		if now.Before(expireTime) {
			return true
		}
		delete(bannedIPs, ip)
	}

	// 3. Verifica Flood (Rate Limit)
	last, exists := ipLastSeen[ip]
	if exists && now.Sub(last) < 100*time.Millisecond {
		bannedUntil := now.Add(10 * time.Minute)
		bannedIPs[ip] = bannedUntil
		log.Printf("[JAIL] 🚫 IP %s banido por 10 min (Flood detectado)", ip)
		return true
	}

	ipLastSeen[ip] = now
	return false
}

// ------------------------------------------
// PROXY SERVER (Porta 8080 / 8081)
// ------------------------------------------

func Start(cfg *config.Config, mgr *manager.GroupManager) {
	// Inicia o Servidor de Matrícula (Enroll) em paralelo
	go StartEnrollment(cfg)

	// Configuração do Proxy
	srv := &http.Server{
		Addr: cfg.Network.ProxyPort,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handle(w, r, mgr)
		}),
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}
	log.Printf("[Proxy] 🛡️  HTTP Proxy em %s (Mode: JAILBREAK)", cfg.Network.ProxyPort)
	log.Fatal(srv.ListenAndServe())
}

// ------------------------------------------
// ENROLLMENT SERVER (Porta 8082 - HTTPS)
// ------------------------------------------

func StartEnrollment(cfg *config.Config) {
	mux := http.NewServeMux()

	// Rota para baixar o CA (Protegida)
	mux.HandleFunc("/ca.crt", func(w http.ResponseWriter, r *http.Request) {
		handleCA(w, r, cfg)
	})

	// Rota para Matrícula (Protegida)
	// Nota: Aqui você deve integrar sua lógica real de gerar certificado
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		handleEnroll(w, r, cfg)
	})

	log.Printf("[Enroll] 📝 API Matrícula em %s (Blindagem Ativa)", cfg.Network.EnrollPort)

	// O Enroll geralmente roda em HTTPS usando o próprio CA do servidor
	// Se você não tiver os arquivos, use ListenAndServe normal (HTTP), mas HTTPS é recomendado.
	err := http.ListenAndServeTLS(cfg.Network.EnrollPort, "certs/ca.crt", "certs/ca.key", mux)
	if err != nil {
		log.Printf("[Enroll] ⚠️  Falha ao iniciar HTTPS (Rodando HTTP?): %v", err)
		// Fallback para HTTP se falhar TLS (opcional)
		http.ListenAndServe(cfg.Network.EnrollPort, mux)
	}
}

// --- HANDLERS DE BLINDAGEM ---

func handleCA(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	// 1. BLINDAGEM: Verifica Segredo
	if cfg.EnrollSecret != "" && r.Header.Get("X-App-Secret") != cfg.EnrollSecret {
		http.NotFound(w, r) // Retorna 404 para enganar scanner
		return
	}

	// 2. Serve o arquivo
	data, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		http.Error(w, "CA Not Found", 404)
		return
	}
	w.Write(data)
}

func handleEnroll(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	// 1. BLINDAGEM: Verifica Segredo
	if cfg.EnrollSecret != "" && r.Header.Get("X-App-Secret") != cfg.EnrollSecret {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	// 2. Lógica de Matrícula (Simplificada para o exemplo)
	// Você deve inserir aqui a chamada para sua função que gera o certificado
	// Exemplo:
	// cert, key, err := pki.GenerateClientCert(...)

	// Como eu não tenho o código do seu gerador de certificados aqui,
	// vou retornar um erro 501 (Not Implemented) para você lembrar de conectar
	// com sua lógica existente de PKI.

	// SE VOCÊ JÁ TINHA ESSA LÓGICA EM OUTRO ARQUIVO, CHAME ELA AQUI.
	http.Error(w, "Enroll Logic needed here", 501)
}

// ------------------------------------------
// LÓGICA DO PROXY (JAIL INTEGRADO)
// ------------------------------------------

func handle(w http.ResponseWriter, r *http.Request, mgr *manager.GroupManager) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}

	// JAIL CHECK
	if checkAndBan(ip) {
		http.Error(w, "IP Banned temporarily", 429)
		return
	}

	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
		http.Error(w, "Auth Required", 407)
		return
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil || !strings.Contains(string(payload), ":") {
		http.Error(w, "Bad Request", 400)
		return
	}
	pair := strings.SplitN(string(payload), ":", 2)

	group, ok := database.AuthenticateUser(pair[0], pair[1], ip)
	if !ok {
		time.Sleep(1 * time.Second)
		http.Error(w, "Forbidden", 403)
		return
	}

	sess := mgr.GetSession(group)
	if sess == nil {
		http.Error(w, "No Agents Online", 503)
		return
	}

	stream, err := sess.Open()
	if err != nil {
		http.Error(w, "Tunnel Error", 502)
		return
	}
	defer stream.Close()

	if r.Method == http.MethodConnect {
		handleTunnel(w, r, stream)
	} else {
		handleHTTP(w, r, stream)
	}
}

func handleTunnel(w http.ResponseWriter, r *http.Request, stream net.Conn) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", 500)
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	fmt.Fprintf(stream, "CONNECT %s HTTP/1.1\r\n\r\n", r.Host)

	go io.Copy(stream, conn)
	io.Copy(conn, stream)
}

func handleHTTP(w http.ResponseWriter, r *http.Request, stream net.Conn) {
	if err := r.Write(stream); err != nil {
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(stream), r)
	if err != nil {
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
