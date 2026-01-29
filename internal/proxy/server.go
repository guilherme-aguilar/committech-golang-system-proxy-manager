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
	"time"

	"proxy-manager/internal/config"
	"proxy-manager/internal/database"
	"proxy-manager/internal/manager"
)

func Start(cfg *config.Config, mgr *manager.GroupManager) {
	srv := &http.Server{
		Addr: cfg.Network.ProxyPort,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handle(w, r, mgr)
		}),
		// Timeouts agressivos para derrubar conexões lentas (Slowloris)
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("[Proxy] 🛡️  HTTP Proxy em %s (Mode: Anti-Brute-Force)", cfg.Network.ProxyPort)
	log.Fatal(srv.ListenAndServe())
}

func handle(w http.ResponseWriter, r *http.Request, mgr *manager.GroupManager) {
	// 1. Pega IP Real (Suporte a Cloudflare/Forwarded)
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}

	// 2. Valida Header de Auth
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
		http.Error(w, "Auth Required", 407)
		return
	}

	// 3. Parse Basic Auth
	// Se o payload for lixo, rejeita rápido
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

	// 4. Autenticação no Banco (O PONTO CRÍTICO)
	group, ok := database.AuthenticateUser(pair[0], pair[1], ip)
	if !ok {
		// --- TARPIT (ARMADILHA) ---
		// Se errou a senha, dorme 2 segundos antes de responder.
		// Isso impede que o atacante teste milhares de senhas por segundo.
		// E libera a CPU para fazer outras coisas.
		log.Printf("[Block] Brute-Force detectado de IP: %s (User: %s)", ip, pair[0])
		time.Sleep(2 * time.Second)
		// --------------------------

		http.Error(w, "Forbidden", 403)
		return
	}

	// 5. Busca Sessão
	sess := mgr.GetSession(group)
	if sess == nil {
		http.Error(w, "No Agents Online", 503)
		return
	}

	// 6. Abre Stream
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
		http.Error(w, err.Error(), 500)
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
		// Não retorna erro HTTP aqui para não quebrar streaming, apenas fecha
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
