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
		// --- TIMEOUTS DE SEGURANÇA ---
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 5 * time.Second, // Importante contra Slowloris
	}
	log.Printf("[Proxy] 🛡️  HTTP Proxy em %s", cfg.Network.ProxyPort)
	log.Fatal(srv.ListenAndServe())
}

func handle(w http.ResponseWriter, r *http.Request, mgr *manager.GroupManager) {
	// 1. Validação de Autenticação (Basic Auth)
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
		http.Error(w, "Auth Required", 407)
		return
	}

	// Parse Basic Auth
	payload, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		http.Error(w, "Bad Auth", 400)
		return
	}

	// 2. Detecção de IP Real
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}

	// 3. Autenticação no Banco
	group, ok := database.AuthenticateUser(pair[0], pair[1], ip)
	if !ok {
		log.Printf("[Block] User %s IP %s negado", pair[0], ip)
		http.Error(w, "Forbidden", 403)
		return
	}

	// 4. Busca Sessão Ativa
	sess := mgr.GetSession(group)
	if sess == nil {
		http.Error(w, "No Agents Online", 503)
		return
	}

	// 5. Abre Stream no Túnel
	stream, err := sess.Open()
	if err != nil {
		http.Error(w, "Tunnel Error", 502)
		return
	}
	defer stream.Close()

	// 6. Roteamento (Connect vs HTTP Padrão)
	if r.Method == http.MethodConnect {
		handleTunnel(w, r, stream)
	} else {
		handleHTTP(w, r, stream)
	}
}

func handleTunnel(w http.ResponseWriter, r *http.Request, stream net.Conn) {
	// HTTPS Tunneling
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

	// Avisa o cliente que o túnel abriu
	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))

	// Envia o CONNECT original para o Agente saber onde ir
	fmt.Fprintf(stream, "CONNECT %s HTTP/1.1\r\n\r\n", r.Host)

	// Pipe bidirecional
	go io.Copy(stream, conn)
	io.Copy(conn, stream)
}

func handleHTTP(w http.ResponseWriter, r *http.Request, stream net.Conn) {
	// HTTP Plain Proxying
	if err := r.Write(stream); err != nil {
		http.Error(w, "Error writing to stream", 502)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(stream), r)
	if err != nil {
		http.Error(w, "Gateway Error", 502)
		return
	}
	defer resp.Body.Close()

	// Copia Headers de volta
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
