package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	// 1. Criar Autoridade Certificadora (CA)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2026),
		Subject: pkix.Name{
			Organization: []string{"Proxy Manager Enterprise CA"},
			CommonName:   "Proxy Manager Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 anos
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	caBytes, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)

	// Salvar CA
	savePEM("certs/ca.crt", "CERTIFICATE", caBytes)
	savePEM("certs/ca.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caPrivKey))

	// 2. Criar Certificado do Servidor (Assinado pela CA)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2027),
		Subject: pkix.Name{
			Organization: []string{"Proxy Manager Server"},
			CommonName:   "localhost", // Common Name
		},
		// --- AQUI ESTÁ A CORREÇÃO MÁGICA ---
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"), // Aceita localhost IPv4
			net.ParseIP("::1"),       // Aceita localhost IPv6
		},
		DNSNames: []string{
			"localhost",    // Aceita nome localhost
			"proxy-server", // Aceita nome de container
		},
		// ------------------------------------
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 ano
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// Adiciona IPs da rede local automaticamente (ex: 192.168.x.x) para você poder conectar de outros PCs
	addLocalIPs(cert)

	serverPrivKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	serverBytes, _ := x509.CreateCertificate(rand.Reader, cert, ca, &serverPrivKey.PublicKey, caPrivKey)

	// Salvar Server
	savePEM("certs/server.crt", "CERTIFICATE", serverBytes)
	savePEM("certs/server.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverPrivKey))

	log.Println("✅ Certificados gerados com sucesso na pasta /certs!")
	log.Println("   Incluindo SANs: localhost, 127.0.0.1 e IPs locais.")
}

func savePEM(file, typeName string, bytes []byte) {
	out, _ := os.Create(file)
	defer out.Close()
	pem.Encode(out, &pem.Block{Type: typeName, Bytes: bytes})
}

func addLocalIPs(cert *x509.Certificate) {
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				cert.IPAddresses = append(cert.IPAddresses, ip)
				log.Printf("   -> Adicionado IP: %s", ip.String())
			}
		}
	}
}
