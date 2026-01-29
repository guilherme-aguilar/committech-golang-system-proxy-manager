package main

import (
	"database/sql"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite" // Driver Pure Go
)

var db *sql.DB

func initDB() {
	var err error
	// Cria o arquivo se não existir
	db, err = sql.Open("sqlite", "./manager.db")
	if err != nil {
		log.Fatal(err)
	}

	// Cria tabela de usuários
	// access_key agora guardará o HASH, não a senha plana
	queryUsers := `
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        access_key TEXT,
        group_name TEXT,
        allowed_ip TEXT
    );`
	if _, err := db.Exec(queryUsers); err != nil {
		log.Fatalf("Erro ao criar tabela users: %v", err)
	}

	// Cria tabela de tokens de grupo
	queryTokens := `
    CREATE TABLE IF NOT EXISTS tokens (
        group_name TEXT PRIMARY KEY,
        token TEXT
    );`
	if _, err := db.Exec(queryTokens); err != nil {
		log.Fatalf("Erro ao criar tabela tokens: %v", err)
	}
}

// --- FUNÇÕES DE SEGURANÇA (BCRYPT) ---

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// --- FUNÇÕES DE USUÁRIO ---

func hasUsers() bool {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}

func addUser(username, plainPassword, group, ip string) error {
	// 1. Criptografa a senha antes de salvar
	hashedPassword, err := hashPassword(plainPassword)
	if err != nil {
		return err
	}

	// 2. Salva o Hash
	_, err = db.Exec("INSERT OR REPLACE INTO users(username, access_key, group_name, allowed_ip) VALUES(?, ?, ?, ?)",
		username, hashedPassword, group, ip)
	return err
}

func authenticateUser(username, plainPassword, remoteIP string) (string, bool) {
	var storedHash, group, allowedIP string

	// Busca o HASH no banco
	err := db.QueryRow("SELECT access_key, group_name, allowed_ip FROM users WHERE username = ?", username).Scan(&storedHash, &group, &allowedIP)
	if err != nil {
		return "", false // Usuário não encontrado
	}

	// 1. Compara a senha enviada com o Hash do banco
	if !checkPasswordHash(plainPassword, storedHash) {
		log.Printf("[Auth] ⛔ Senha incorreta para user: %s", username)
		return "", false
	}

	// 2. Validação de IP (Aceita * ou IP exato)
	if allowedIP != "*" && allowedIP != remoteIP {
		log.Printf("[Auth] ⛔ IP não autorizado para user %s: %s (Esperado: %s)", username, remoteIP, allowedIP)
		return "", false
	}

	return group, true
}

func getAllUsers(groupFilter string) []map[string]string {
	query := "SELECT username, group_name, allowed_ip FROM users"
	var rows *sql.Rows
	var err error

	if groupFilter != "" {
		query += " WHERE group_name = ?"
		rows, err = db.Query(query, groupFilter)
	} else {
		rows, err = db.Query(query)
	}

	if err != nil {
		return nil
	}
	defer rows.Close()

	var results []map[string]string
	for rows.Next() {
		var u, g, i string
		rows.Scan(&u, &g, &i)
		results = append(results, map[string]string{
			"username": u,
			"group":    g,
			"ip":       i,
		})
	}
	return results
}

func deleteUser(username string) {
	db.Exec("DELETE FROM users WHERE username = ?", username)
}

// --- FUNÇÕES DE GRUPOS E TOKENS ---

func getAllGroups() []string {
	// Pega grupos únicos da tabela de usuários e tokens
	// Lógica simplificada: listar tokens como "grupos ativos"
	rows, err := db.Query("SELECT group_name FROM tokens")
	if err != nil {
		return []string{}
	}
	defer rows.Close()
	var groups []string
	for rows.Next() {
		var g string
		rows.Scan(&g)
		groups = append(groups, g)
	}
	return groups
}

func createGroup(name string) {
	// Apenas garante que o grupo tenha um token
	generateAndSetToken(name)
}

func deleteGroup(name string) {
	db.Exec("DELETE FROM tokens WHERE group_name = ?", name)
	db.Exec("DELETE FROM users WHERE group_name = ?", name)
}

func toggleGroupStatus(name, status string) {
	// Implementação futura: Adicionar coluna 'active' na tabela tokens
	// Por enquanto não faz nada no DB
}

func getGroupVersion(group string) int {
	// Implementação futura para rotação de versão
	return 1
}

func isGroupValidStrict(group string, version int) bool {
	// Verifica se o grupo existe na tabela de tokens
	var exists int
	db.QueryRow("SELECT 1 FROM tokens WHERE group_name = ?", group).Scan(&exists)
	return exists == 1
}

// --- TOKEN MANAGEMENT ---

func generateAndSetToken(group string) string {
	// Gera token aleatório simples (pode melhorar se quiser)
	token, _ := hashPassword(time.Now().String() + group) // Usa o hash como token randômico
	token = token[:16]                                    // Pega os primeiros 16 chars

	db.Exec("INSERT OR REPLACE INTO tokens(group_name, token) VALUES(?, ?)", group, token)
	return token
}

func getGroupForToken(token string) (string, bool) {
	var group string
	err := db.QueryRow("SELECT group_name FROM tokens WHERE token = ?", token).Scan(&group)
	if err != nil {
		return "", false
	}
	return group, true
}

func getAllTokens(groupFilter string) map[string]string {
	results := make(map[string]string)
	rows, err := db.Query("SELECT group_name, token FROM tokens")
	if err != nil {
		return results
	}
	defer rows.Close()
	for rows.Next() {
		var g, t string
		rows.Scan(&g, &t)
		if groupFilter == "" || groupFilter == g {
			results[g] = t
		}
	}
	return results
}

func deleteToken(token string) {
	db.Exec("DELETE FROM tokens WHERE token = ?", token)
}
