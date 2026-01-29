package api

import (
	"io"       // <--- Import Novo
	"log/slog" // <--- Import Novo
	"net/http"
	"strings"

	"proxy-manager/internal/config"
	"proxy-manager/internal/database"
	"proxy-manager/internal/manager"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-fuego/fuego"
)

type Server struct {
	Config  *config.Config
	Manager *manager.GroupManager
}

// --- Models ---

type UserReq struct {
	Username  string `json:"username" validate:"required"`
	AccessKey string `json:"access_key" validate:"required"`
	Group     string `json:"group" validate:"required"`
	IP        string `json:"ip"`
}

type GroupReq struct {
	Name string `json:"name" validate:"required"`
}

type TokenReq struct {
	Group string `json:"group" validate:"required"`
}

// --- Server Setup ---

func (s *Server) Start() {
	// 1. Configura o Servidor Fuego
	srv := fuego.NewServer(
		fuego.WithAddr(s.Config.Network.AdminPort),
		fuego.WithEngineOptions(
			fuego.WithOpenAPIConfig(fuego.OpenAPIConfig{
				Info: &openapi3.Info{
					Title:       "Proxy Manager Enterprise",
					Version:     "2.0.0",
					Description: "API de Gerenciamento de Proxies e Usuários",
				},
			}),
		),
		// CORREÇÃO AQUI: Usamos um Handler do slog que joga tudo fora (io.Discard)
		fuego.WithLogHandler(slog.NewTextHandler(io.Discard, nil)),
	)

	// 2. Middleware Global (Autenticação)
	fuego.Use(srv, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// Libera rotas públicas (Dashboard, Swagger, Health checks)
			if r.URL.Path == "/" ||
				r.URL.Path == "/dashboard.html" ||
				r.URL.Path == "/openapi.json" ||
				strings.HasPrefix(r.URL.Path, "/swagger") ||
				strings.HasPrefix(r.URL.Path, "/.well-known") {
				next.ServeHTTP(w, r)
				return
			}

			// Validação do Token Bearer
			token := r.Header.Get("Authorization")
			if token != "Bearer "+s.Config.Security.AdminToken {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// 3. Registro de Rotas
	fuego.Get(srv, "/status", s.handleStatus)
	fuego.Get(srv, "/users", s.handleGetUsers)
	fuego.Get(srv, "/proxy-tokens", s.handleGetTokens)
	fuego.Get(srv, "/groups", s.handleGetGroups)

	fuego.Post(srv, "/users", s.handleCreateUser)
	fuego.Post(srv, "/proxy-tokens", s.handleCreateToken)
	fuego.Post(srv, "/groups", s.handleCreateGroup)

	fuego.Delete(srv, "/users", s.handleDeleteUser)
	fuego.Delete(srv, "/proxy-tokens", s.handleDeleteToken)
	fuego.Delete(srv, "/groups", s.handleDeleteGroup)

	dashboardHandler := func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./assets/dashboard.html")
	}

	fuego.GetStd(srv, "/dashboard.html", dashboardHandler)
	fuego.GetStd(srv, "/", dashboardHandler)

	// Inicia o servidor
	srv.Run()
}

// --- Handlers ---

func (s *Server) handleStatus(c fuego.ContextNoBody) (map[string][]map[string]string, error) {
	return s.Manager.GetStatus(c.QueryParam("group")), nil
}

func (s *Server) handleGetUsers(c fuego.ContextNoBody) ([]map[string]string, error) {
	return database.GetAllUsers(c.QueryParam("group")), nil
}

func (s *Server) handleCreateUser(c fuego.ContextWithBody[UserReq]) (map[string]string, error) {
	req, err := c.Body()
	if err != nil {
		return nil, err
	}

	err = database.AddUser(req.Username, req.AccessKey, req.Group, req.IP)
	if err != nil {
		return nil, err
	}

	return map[string]string{"status": "created"}, nil
}

func (s *Server) handleDeleteUser(c fuego.ContextNoBody) (map[string]string, error) {
	database.DeleteUser(c.QueryParam("username"))
	return map[string]string{"status": "deleted"}, nil
}

func (s *Server) handleGetTokens(c fuego.ContextNoBody) (map[string]string, error) {
	return database.GetAllTokens(c.QueryParam("group")), nil
}

func (s *Server) handleCreateToken(c fuego.ContextWithBody[TokenReq]) (map[string]string, error) {
	req, err := c.Body()
	if err != nil {
		return nil, err
	}

	token := database.GenerateAndSetToken(req.Group)
	s.Manager.ForceDisconnectGroup(req.Group)
	return map[string]string{"token": token}, nil
}

func (s *Server) handleDeleteToken(c fuego.ContextNoBody) (map[string]string, error) {
	database.DeleteToken(c.QueryParam("token"))
	return map[string]string{"status": "deleted"}, nil
}

func (s *Server) handleGetGroups(c fuego.ContextNoBody) ([]string, error) {
	return database.GetAllGroups(), nil
}

func (s *Server) handleCreateGroup(c fuego.ContextWithBody[GroupReq]) (map[string]string, error) {
	req, err := c.Body()
	if err != nil {
		return nil, err
	}

	database.GenerateAndSetToken(req.Name)
	return map[string]string{"status": "created"}, nil
}

func (s *Server) handleDeleteGroup(c fuego.ContextNoBody) (map[string]string, error) {
	group := c.QueryParam("name")
	database.DeleteGroup(group)
	s.Manager.ForceDisconnectGroup(group)
	return map[string]string{"status": "deleted"}, nil
}
