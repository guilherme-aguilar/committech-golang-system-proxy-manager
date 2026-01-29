package config

import (
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	// --- ADICIONE ESTE CAMPO (Para corrigir o erro undefined) ---
	EnrollSecret string `toml:"enroll_secret"`

	Network struct {
		EnrollPort string `toml:"enroll_port"`
		TunnelPort string `toml:"tunnel_port"`
		ProxyPort  string `toml:"proxy_port"`
		AdminPort  string `toml:"admin_port"`
	} `toml:"network"`

	Security struct {
		AdminToken string `toml:"admin_token"`
	} `toml:"security"`
}

func Load(path string) (*Config, error) {
	cfg := &Config{}

	// Defaults
	cfg.Network.EnrollPort = ":8082"
	cfg.Network.TunnelPort = ":8081"
	cfg.Network.ProxyPort = ":8080"
	cfg.Network.AdminPort = ":8083"
	cfg.Security.AdminToken = "admin-secret-123"

	// Opcional: Default do segredo (embora ideal seja vir do TOML)
	cfg.EnrollSecret = ""

	if _, err := os.Stat(path); err == nil {
		if _, err := toml.DecodeFile(path, cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}
