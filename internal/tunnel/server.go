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

func Start(cfg *config.Config, mgr *manager.GroupManager, caCert, caKey []byte, serverCert tls.Certificate) {
	go startEnrollment(cfg.Network.EnrollPort, caCert, caKey, serverCert)
	go startTunnel(cfg.Network.TunnelPort, caCert, serverCert, mgr)
}

func startEnrollment(addr string, caCert, caKey []byte, serverCert tls.Certificate) {
	mux := http.NewServeMux()

	// Rota para baixar o CA (opcional, útil para debug)
	mux.HandleFunc("/ca.crt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(caCert)
	})

	// Rota de Matrícula
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", 405)
			return
		}
		var req struct{ Token, Name string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", 400)
			return
		}

		group, exists := database.GetGroupForToken(req.Token)
		if !exists {
			log.Printf("[Enroll] Tentativa falha com token: %s", req.Token)
			http.Error(w, "Token inválido", 403)
			return
		}

		// Gera certificado cliente
		cert, key := generateSignedCert(req.Name, group, caCert, caKey)

		log.Printf("[Enroll] Sucesso: %s (Grupo: %s)", req.Name, group)
		json.NewEncoder(w).Encode(map[string]string{"cert": string(cert), "key": string(key)})
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{serverCert}},
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second, // Proteção
	}
	log.Printf("[Enroll] 📝 API Matrícula em %s (HTTPS)", addr)
	// Em produção, isso deve rodar em HTTPS. Certifique-se que serverCert é válido.
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func startTunnel(addr string, caCert []byte, serverCert tls.Certificate, mgr *manager.GroupManager) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)

	ln, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // Exige mTLS
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("[Tunnel] 🔒 mTLS Listener em %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// --- CORREÇÃO CRÍTICA DE CPU ---
			// Se der erro no Accept (ex: limite de arquivos), espera um pouco
			// antes de tentar de novo, senão a CPU vai a 100% num loop infinito.
			log.Printf("[Tunnel Error] Accept falhou: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		// Se deu certo, joga pra goroutine
		go handleConn(conn, mgr)
	}
}

func handleConn(conn net.Conn, mgr *manager.GroupManager) {
	// Garante Handshake para ler os certificados
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

	// Extrai dados do certificado do cliente
	cert := state.PeerCertificates[0]
	clientID := cert.Subject.CommonName

	// O grupo está na OU (Organization Unit), formato "grupo:id"
	if len(cert.Subject.OrganizationalUnit) == 0 {
		conn.Close()
		return
	}
	group := strings.Split(cert.Subject.OrganizationalUnit[0], ":")[0]

	// Inicia multiplexador Yamux
	session, err := yamux.Client(conn, nil)
	if err != nil {
		log.Printf("[Tunnel] Erro Yamux cliente %s: %v", clientID, err)
		conn.Close()
		return
	}

	mgr.RegisterClient(clientID, group, session)
}

func generateSignedCert(name, group string, caCert, caKey []byte) ([]byte, []byte) {
	pair, _ := tls.X509KeyPair(caCert, caKey)
	root, _ := x509.ParseCertificate(pair.Certificate[0])

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Template do certificado do Cliente
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		// Colocamos o Grupo na OU para identificar depois
		Subject:     pkix.Name{CommonName: name, OrganizationalUnit: []string{group + ":1"}},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1 Ano
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	der, _ := x509.CreateCertificate(rand.Reader, tmpl, root, &priv.PublicKey, pair.PrivateKey)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPEM, keyPEM
}
