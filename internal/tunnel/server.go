package tunnel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"proxy-manager/internal/config"
	"proxy-manager/internal/database"
	"proxy-manager/internal/manager"

	"github.com/hashicorp/yamux"
)

// Start inicia os serviços do Tunnel e Enrollment
func Start(cfg *config.Config, mgr *manager.GroupManager, caCert, caKey []byte, serverCert tls.Certificate) {
	// Inicia Enrollment (Porta 8082)
	go startEnrollment(cfg.Network.EnrollPort, caCert, caKey, serverCert, cfg.EnrollSecret)

	// Inicia Tunnel (Porta 8081)
	go startTunnel(cfg.Network.TunnelPort, caCert, serverCert, mgr)
}

func startEnrollment(addr string, caCert, caKey []byte, serverCert tls.Certificate, enrollSecret string) {
	mux := http.NewServeMux()

	// Rota para baixar o CA (Protegida por Secret)
	mux.HandleFunc("/ca.crt", func(w http.ResponseWriter, r *http.Request) {
		// BLINDAGEM
		if enrollSecret != "" && r.Header.Get("X-App-Secret") != enrollSecret {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(caCert)
	})

	// Rota de Matrícula
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		// BLINDAGEM
		if enrollSecret != "" && r.Header.Get("X-App-Secret") != enrollSecret {
			http.NotFound(w, r)
			return
		}

		if r.Method != "POST" {
			http.Error(w, "Method not allowed", 405)
			return
		}

		var req struct{ Token, Name string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", 400)
			return
		}

		// Valida Token
		group, exists := database.GetGroupForToken(req.Token)
		if !exists {
			log.Printf("[Enroll] ❌ Token inválido: %s", req.Token)
			time.Sleep(1 * time.Second) // Delay para evitar brute-force
			http.Error(w, "Token inválido", 403)
			return
		}

		// Gera certificado
		cert, key := generateSignedCert(req.Name, group, caCert, caKey)

		log.Printf("[Enroll] ✅ Agente matriculado: %s (Grupo: %s)", req.Name, group)
		json.NewEncoder(w).Encode(map[string]string{
			"cert": string(cert),
			"key":  string(key),
		})
	})

	srv := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{serverCert}},
		// Timeouts de Segurança para a API de Enroll (Aqui pode ter timeout curto)
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("[Enroll] 📝 API Matrícula em %s (HTTPS + Blindagem)", addr)
	// Se der erro de bind, loga e continua (não mata o tunnel)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Printf("[Enroll] ❌ Erro ao iniciar Enroll: %v", err)
	}
}

func startTunnel(addr string, caCert []byte, serverCert tls.Certificate, mgr *manager.GroupManager) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)

	ln, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		log.Fatal(err) // Se o túnel não subir, o app deve morrer
	}

	log.Printf("[Tunnel] 🔒 Listener mTLS em %s (No-Timeout)", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[Tunnel] Accept erro: %v", err)
			time.Sleep(100 * time.Millisecond) // Proteção CPU 100%
			continue
		}

		// Handshake em goroutine
		go handleConn(conn, mgr)
	}
}

func handleConn(conn net.Conn, mgr *manager.GroupManager) {
	tlsConn := conn.(*tls.Conn)

	// Timeout APENAS para o Handshake inicial
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return
	}
	// REMOVE O TIMEOUT para a conexão de longa duração
	tlsConn.SetDeadline(time.Time{})

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		conn.Close()
		return
	}

	cert := state.PeerCertificates[0]
	clientID := cert.Subject.CommonName

	if len(cert.Subject.OrganizationalUnit) == 0 {
		conn.Close()
		return
	}
	// Formato "grupo:id"
	group := strings.Split(cert.Subject.OrganizationalUnit[0], ":")[0]

	session, err := yamux.Client(conn, nil)
	if err != nil {
		log.Printf("[Tunnel] Erro Yamux %s: %v", clientID, err)
		conn.Close()
		return
	}

	mgr.RegisterClient(clientID, group, session)
}

func generateSignedCert(name, group string, caCert, caKey []byte) ([]byte, []byte) {
	pair, _ := tls.X509KeyPair(caCert, caKey)
	root, _ := x509.ParseCertificate(pair.Certificate[0])

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name, OrganizationalUnit: []string{group + ":1"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 ano
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, _ := x509.CreateCertificate(rand.Reader, tmpl, root, &priv.PublicKey, pair.PrivateKey)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPEM, keyPEM
}
