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

// --- SISTEMA DE PRISÃO (JAIL) ---
var (
	// Controle de Concorrência
	jailMutex sync.RWMutex

	// Mapa de IPs Banidos: IP -> Hora que o ban acaba
	bannedIPs = make(map[string]time.Time)

	// Mapa de Última Requisição (para detectar flood)
	ipLastSeen = make(map[string]time.Time)

	// Limpeza de memória
	cleanupTime = time.Now()
)

// checkAndBan verifica se o IP deve ser bloqueado ou se já está banido
func checkAndBan(ip string) (banned bool) {
	jailMutex.Lock()
	defer jailMutex.Unlock()

	now := time.Now()

	// 1. Limpeza automática a cada 10 minutos para economizar RAM
	if time.Since(cleanupTime) > 10*time.Minute {
		// Remove IPs cujo ban já expirou
		for k, v := range bannedIPs {
			if now.After(v) {
				delete(bannedIPs, k)
			}
		}
		// Zera o histórico de requisições antigas
		ipLastSeen = make(map[string]time.Time)
		cleanupTime = now
	}

	// 2. VERIFICA SE JÁ ESTÁ PRESO
	if expireTime, isBanned := bannedIPs[ip]; isBanned {
		if now.Before(expireTime) {
			return true // Ainda está banido
		}
		delete(bannedIPs, ip) // Pena cumprida, solta o meliante
	}

	// 3. VERIFICA FLOOD (RATE LIMIT)
	last, exists := ipLastSeen[ip]

	// Se fez requisição há menos de 1 segundo
	if exists && now.Sub(last) < 1000*time.Millisecond {
		// --- O JULGAMENTO ---
		// O usuário floodou. Em vez de só negar, PRENDE ELE.
		// Banido por 10 Minutos.
		bannedUntil := now.Add(10 * time.Minute)
		bannedIPs[ip] = bannedUntil

		// Log para você ver o sistema funcionando (opcional, pode remover se poluir muito)
		log.Printf("[JAIL] 🚫 IP %s banido por 10 min (Flood detectado)", ip)

		return true
	}

	// Tudo limpo, atualiza o visto
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
	log.Printf("[Proxy] 🛡️  HTTP Proxy em %s (Mode: JAILBREAK - Banimento em Memória)", cfg.Network.ProxyPort)
	log.Fatal(srv.ListenAndServe())
}

func handle(w http.ResponseWriter, r *http.Request, mgr *manager.GroupManager) {
	// 1. Pega IP Real (Funciona mesmo com NAT/Proxy se configurado X-Forwarded-For)
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}

	// 2. CHECK DE PRISÃO (Custo de CPU quase zero)
	if checkAndBan(ip) {
		// Retorna erro seco e fecha a conexão.
		// Não gasta CPU com banco de dados nem lógica.
		http.Error(w, "IP Banned temporarily", 429)
		return
	}

	// 3. Valida Auth
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
		http.Error(w, "Auth Required", 407)
		return
	}

	// Parse rápido
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

	// 4. Autenticação no Banco (Pesado)
	group, ok := database.AuthenticateUser(pair[0], pair[1], ip)
	if !ok {
		// Se errou a senha, dorme 1s para desencorajar e retorna
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
