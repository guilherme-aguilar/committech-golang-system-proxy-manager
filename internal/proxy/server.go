package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
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

// --- SISTEMA DE RATE LIMIT (O Porteiro) ---
var (
	ipMutex    sync.Mutex
	ipLastSeen = make(map[string]time.Time)
	// Limpa o mapa a cada 5 minutos para não estourar memória
	cleanupTime = time.Now()
)

func isRateLimited(ip string) bool {
	ipMutex.Lock()
	defer ipMutex.Unlock()

	// Limpeza automática de memória se o mapa ficar muito grande
	if len(ipLastSeen) > 5000 || time.Since(cleanupTime) > 5*time.Minute {
		ipLastSeen = make(map[string]time.Time)
		cleanupTime = time.Now()
	}

	last, exists := ipLastSeen[ip]
	now := time.Now()

	// Se o IP fez requisição há menos de 1 segundo, BLOQUEIA.
	// Isso impede o Brute-Force rápido.
	if exists && now.Sub(last) < 1000*time.Millisecond {
		return true
	}

	ipLastSeen[ip] = now
	return false
}

// ------------------------------------------

func Start(cfg *config.Config, mgr *manager.GroupManager) {
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
	log.Printf("[Proxy] 🛡️  HTTP Proxy em %s (Proteção: Rate Limit Ativo)", cfg.Network.ProxyPort)
	log.Fatal(srv.ListenAndServe())
}

func handle(w http.ResponseWriter, r *http.Request, mgr *manager.GroupManager) {
	// 1. Pega IP Real
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}

	// 2. CHECK DE RATE LIMIT (ANTES DE TUDO)
	// Se o cara está floodando, rejeita aqui e salva a CPU.
	if isRateLimited(ip) {
		// Retorna 429 Too Many Requests sem processar nada pesado
		http.Error(w, "Too Many Requests", 429)
		return
	}

	// 3. Valida Auth
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
		http.Error(w, "Auth Required", 407)
		return
	}

	// Parse rápido (custo de CPU baixo)
	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		http.Error(w, "Bad Request", 400)
		return
	}
	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		http.Error(w, "Bad Auth", 400)
		return
	}

	// 4. Autenticação no Banco (Custo de CPU ALTO)
	// Agora só chega aqui quem passou pelo Rate Limit (1 req/segundo)
	group, ok := database.AuthenticateUser(pair[0], pair[1], ip)
	if !ok {
		// Tarpit leve de 1s para desencorajar
		time.Sleep(1 * time.Second)
		http.Error(w, "Forbidden", 403)
		return
	}

	// 5. Sessão e Túnel
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
