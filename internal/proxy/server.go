package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt" // Usaremos FMT para forçar a saída
	"io"
	"log"
	"net"
	"net/http"
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
	// Limpeza
	if time.Since(cleanupTime) > 10*time.Minute {
		for k, v := range bannedIPs {
			if now.After(v) {
				delete(bannedIPs, k)
			}
		}
		ipLastSeen = make(map[string]time.Time)
		cleanupTime = now
	}
	// Banimento
	if expireTime, isBanned := bannedIPs[ip]; isBanned {
		if now.Before(expireTime) {
			return true
		}
		delete(bannedIPs, ip)
	}
	// Rate Limit 10ms
	last, exists := ipLastSeen[ip]
	if exists && now.Sub(last) < 10*time.Millisecond {
	}
	ipLastSeen[ip] = now
	return false
}

// ------------------------------------------
// PROXY SERVER
// ------------------------------------------

func Start(cfg *config.Config, mgr *manager.GroupManager) {
	srv := &http.Server{
		Addr: cfg.Network.ProxyPort,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handle(w, r, mgr)
		}),
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}
	// MUDEI O TEXTO PARA VOCÊ TER CERTEZA QUE ATUALIZOU
	fmt.Printf("[Proxy] 🛡️  HTTP Proxy rodando em %s (FMT PRINT ATIVO)\n", cfg.Network.ProxyPort)
	log.Fatal(srv.ListenAndServe())
}

// ------------------------------------------
// LÓGICA DO PROXY
// ------------------------------------------

func handle(w http.ResponseWriter, r *http.Request, mgr *manager.GroupManager) {
	// 1. Identifica IP e PORTA (Alteração aqui)
	ip, port, _ := net.SplitHostPort(r.RemoteAddr)

	// Se houver X-Forwarded-For, usamos o IP real do cliente,
	// mas mantemos a porta da conexão TCP original
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}

	if checkAndBan(ip) {
		http.Error(w, "IP Banned", 429)
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
	username := pair[0]
	password := pair[1]

	group, ok := database.AuthenticateUser(username, password, ip)
	if !ok {
		// Log de erro (Com porta)
		fmt.Printf("[Auth] ❌ Falha login: %s (IP: %s:%s)\n", username, ip, port)
		time.Sleep(1 * time.Second)
		http.Error(w, "Forbidden", 403)
		return
	}

	sess := mgr.GetSession(group)
	if sess == nil {
		fmt.Printf("[Proxy] ⚠️  Grupo '%s' sem agentes online\n", group)
		http.Error(w, "No Agents Online", 503)
		return
	}

	// --- LOG DE SUCESSO (Com Src Addr e Src Port) ---
	// \033[32m deixa o texto verde no terminal
	// Adicionei | Src: %s:%s | passando 'ip' e 'port'
	fmt.Printf("\033[32m[Proxy] 🟢 REQ: %s %s | Src: %s:%s | User: %s -> Agente: %s\033[0m\n", r.Method, r.Host, ip, port, username, group)
	// -------------------------------------------------

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
