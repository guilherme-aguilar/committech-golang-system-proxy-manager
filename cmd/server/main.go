package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"

	"proxy-manager/internal/api"
	"proxy-manager/internal/config"
	"proxy-manager/internal/database"
	"proxy-manager/internal/manager"
	"proxy-manager/internal/proxy"
	"proxy-manager/internal/tunnel"
)

func main() {
	log.Println("[Init] Iniciando Proxy Manager Enterprise v2.0 (Fuego Edition)")

	confPath := flag.String("config", "server.toml", "Path config")
	flag.Parse()
	cfg, err := config.Load(*confPath)
	if err != nil {
		log.Fatal(err)
	}

	// Init DB e Bootstrapping
	database.Init("./manager.db")
	if !database.HasUsers() {
		log.Println("[Init] Banco vazio. Criando admin...")
		pass := database.GenerateRandomString(12)
		database.AddUser("admin", pass, "financeiro", "*")
		token := database.GenerateAndSetToken("financeiro")
		fmt.Printf("\n!!! ADMIN CRIADO !!!\nPass: %s\nToken: %s\n\n", pass, token)
	}

	// Certs
	caCert, _ := os.ReadFile("certs/ca.crt")
	caKey, _ := os.ReadFile("certs/ca.key")
	srvCert, _ := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")

	// Start Services
	mgr := manager.New()

	go tunnel.Start(cfg, mgr, caCert, caKey, srvCert)
	go proxy.Start(cfg, mgr)

	apiSrv := &api.Server{Config: cfg, Manager: mgr}
	apiSrv.Start() // Bloqueia aqui
}
