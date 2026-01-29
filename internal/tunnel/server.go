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
	mux.HandleFunc("/ca.crt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(caCert)
	})
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			return
		}
		var req struct{ Token, Name string }
		json.NewDecoder(r.Body).Decode(&req)

		group, exists := database.GetGroupForToken(req.Token)
		if !exists {
			http.Error(w, "Token inválido", 403)
			return
		}
		cert, key := generateSignedCert(req.Name, group, caCert, caKey)
		json.NewEncoder(w).Encode(map[string]string{"cert": string(cert), "key": string(key)})
	})

	srv := &http.Server{
		Addr: addr, Handler: mux,
		TLSConfig:   &tls.Config{Certificates: []tls.Certificate{serverCert}},
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
	}
	log.Printf("[Enroll] 📝 API Matrícula em %s", addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func startTunnel(addr string, caCert []byte, serverCert tls.Certificate, mgr *manager.GroupManager) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	ln, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool, ClientAuth: tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("[Tunnel] 🔒 mTLS Listener em %s", addr)
	for {
		conn, err := ln.Accept()
		if err == nil {
			go handleConn(conn, mgr)
		}
	}
}

func handleConn(conn net.Conn, mgr *manager.GroupManager) {
	tlsConn := conn.(*tls.Conn)
	tlsConn.Handshake()
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		conn.Close()
		return
	}

	cert := state.PeerCertificates[0]
	clientID := cert.Subject.CommonName
	group := strings.Split(cert.Subject.OrganizationalUnit[0], ":")[0]

	session, err := yamux.Client(conn, nil)
	if err != nil {
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
		NotBefore:    time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, root, &priv.PublicKey, pair.PrivateKey)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
}
