package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"proxy-manager/internal/api"
	"proxy-manager/internal/config"
	"proxy-manager/internal/database"
	"proxy-manager/internal/manager"
	"proxy-manager/internal/proxy"
	"proxy-manager/internal/tunnel"
)

func main() {
	// --- FORÇA O LOG A SAIR NO TERMINAL ---
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	// --------------------------------------

	log.Println("[Init] Iniciando Proxy Manager Enterprise v2.2 (Log Fix)")

	// 1. Carrega Configuração
	confPath := flag.String("config", "server.toml", "Path config")
	flag.Parse()
	cfg, err := config.Load(*confPath)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Banco de Dados
	database.Init("./manager.db")
	if !database.HasUsers() {
		log.Println("[Init] Banco vazio. Criando admin...")
		pass := database.GenerateRandomString(12)
		database.AddUser("admin", pass, "financeiro", "*")
		token := database.GenerateAndSetToken("financeiro")
		fmt.Printf("\n!!! ADMIN CRIADO !!!\nPass: %s\nToken: %s\n\n", pass, token)
	}

	// 3. Certificados
	caCert, caKey, serverCert := loadOrGenCertificates()

	// 4. Gerenciador
	mgr := manager.New(cfg)

	// 5. Inicia Serviços (Tunnel e Proxy)
	go tunnel.Start(cfg, mgr, caCert, caKey, serverCert)

	// Inicia Proxy HTTP (Aqui que queremos ver os logs)
	go proxy.Start(cfg, mgr)

	time.Sleep(500 * time.Millisecond)

	// 6. Inicia API (Bloqueia execução)
	log.Printf("[API] 🚀 Admin API rodando na porta %s", cfg.Network.AdminPort)
	apiSrv := &api.Server{Config: cfg, Manager: mgr}
	apiSrv.Start()
}

// --- Funções de Certificado (Mantive igual, pois já funcionam) ---
func loadOrGenCertificates() ([]byte, []byte, tls.Certificate) {
	if _, err := os.Stat("certs"); os.IsNotExist(err) {
		os.Mkdir("certs", 0755)
	}
	caCert, err1 := os.ReadFile("certs/ca.crt")
	caKey, err2 := os.ReadFile("certs/ca.key")

	if err1 != nil || err2 != nil {
		log.Println("[Boot] ⚠️  Certificados não encontrados. Gerando novos...")
		return generateCA()
	}

	serverCert, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		log.Println("[Boot] ⚠️  Erro no par de chaves. Regenerando...")
		return generateCA()
	}
	return caCert, caKey, serverCert
}

func generateCA() ([]byte, []byte, tls.Certificate) {
	caPrivKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Committech Proxy Manager"},
			CommonName:   "localhost",
		},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})

	os.WriteFile("certs/ca.crt", caPEM, 0644)
	os.WriteFile("certs/ca.key", keyPEM, 0600)
	os.WriteFile("certs/server.crt", caPEM, 0644)
	os.WriteFile("certs/server.key", keyPEM, 0600)

	serverCert, _ := tls.X509KeyPair(caPEM, keyPEM)
	log.Println("[Boot] ✅ Certificados regenerados.")
	return caPEM, keyPEM, serverCert
}
