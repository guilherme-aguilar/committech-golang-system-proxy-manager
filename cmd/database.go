package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

// --- ESTRUTURAS ---
type GroupData struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Version int    `json:"version"` // NOVO
}

type TokenData struct {
	Token string `json:"token"`
	Group string `json:"group"`
}

type UserData struct {
	Username  string `json:"username"`
	AccessKey string `json:"access_key"`
	Group     string `json:"group"`
	IP        string `json:"ip"`
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./manager.db")
	if err != nil {
		log.Fatal(err)
	}

	createTables := `
    CREATE TABLE IF NOT EXISTS groups (
        name TEXT PRIMARY KEY,
        status TEXT DEFAULT 'active',
        version INTEGER DEFAULT 1  -- NOVO: Controle de Rotação
    );
    CREATE TABLE IF NOT EXISTS enrollment_tokens (
        token TEXT PRIMARY KEY,
        group_name TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS api_users (
        username TEXT PRIMARY KEY,
        access_key TEXT NOT NULL,
        assigned_group TEXT NOT NULL,
        allowed_origin_ip TEXT DEFAULT '*' 
    );
    `
	_, err = db.Exec(createTables)
	if err != nil {
		log.Fatal("Erro criando tabelas:", err)
	}
}

func hasUsers() bool {
	var count int
	db.QueryRow("SELECT count(*) FROM api_users").Scan(&count)
	return count > 0
}

// --- GRUPOS (COM VERSÃO) ---

func getAllGroups() []GroupData {
	rows, err := db.Query("SELECT name, status, version FROM groups")
	if err != nil {
		return []GroupData{}
	}
	defer rows.Close()

	var list []GroupData
	for rows.Next() {
		var g GroupData
		rows.Scan(&g.Name, &g.Status, &g.Version)
		list = append(list, g)
	}
	return list
}

func createGroup(name string) error {
	// Cria com versão 1 por padrão
	_, err := db.Exec("INSERT OR IGNORE INTO groups (name, status, version) VALUES (?, 'active', 1)", name)
	return err
}

func deleteGroup(name string) {
	db.Exec("DELETE FROM enrollment_tokens WHERE group_name = ?", name)
	db.Exec("DELETE FROM api_users WHERE assigned_group = ?", name)
	db.Exec("DELETE FROM groups WHERE name = ?", name)
}

func toggleGroupStatus(name string, status string) {
	db.Exec("UPDATE groups SET status = ? WHERE name = ?", status, name)
}

// GET VERSION (Novo Helper)
func getGroupVersion(name string) int {
	var v int
	db.QueryRow("SELECT version FROM groups WHERE name = ?", name).Scan(&v)
	return v
}

// VALIDAÇÃO RIGOROSA (Nome + Status + Versão)
func isGroupValidStrict(name string, clientVersion int) bool {
	var currentVersion int
	var status string

	err := db.QueryRow("SELECT status, version FROM groups WHERE name = ?", name).Scan(&status, &currentVersion)

	if err != nil {
		return false
	} // Grupo não existe
	if status != "active" {
		return false
	} // Grupo inativo
	if clientVersion != currentVersion {
		return false
	} // VERSÃO ANTIGA (Certificado revogado por rotação)

	return true
}

// --- TOKENS (COM ROTAÇÃO DE VERSÃO) ---

func getAllTokens(groupFilter string) []TokenData {
	query := "SELECT token, group_name FROM enrollment_tokens"
	var rows *sql.Rows
	var err error
	if groupFilter != "" && groupFilter != "all" {
		rows, err = db.Query(query+" WHERE group_name = ?", groupFilter)
	} else {
		rows, err = db.Query(query)
	}
	if err != nil {
		return []TokenData{}
	}
	defer rows.Close()
	var list []TokenData
	for rows.Next() {
		var t TokenData
		rows.Scan(&t.Token, &t.Group)
		list = append(list, t)
	}
	return list
}

// GERA TOKEN E SOBE VERSÃO DO GRUPO (Invalidando certs antigos)
func generateAndSetToken(group string) string {
	createGroup(group)

	// 1. Incrementa a versão do grupo (Isso mata as conexões antigas)
	db.Exec("UPDATE groups SET version = version + 1 WHERE name = ?", group)

	// 2. Gera Token
	b := make([]byte, 16)
	rand.Read(b)
	newToken := hex.EncodeToString(b)

	// 3. Substitui token no banco
	db.Exec("DELETE FROM enrollment_tokens WHERE group_name = ?", group)
	db.Exec("INSERT INTO enrollment_tokens (token, group_name) VALUES (?, ?)", newToken, group)

	return newToken
}

func deleteToken(token string) {
	db.Exec("DELETE FROM enrollment_tokens WHERE token = ?", token)
}

func getGroupForToken(token string) (string, bool) {
	var group string
	err := db.QueryRow("SELECT group_name FROM enrollment_tokens WHERE token = ?", token).Scan(&group)
	return group, err == nil
}

// --- USERS ---
// (Mesmo código de users de antes)
func getAllUsers(groupFilter string) []UserData {
	query := "SELECT username, access_key, assigned_group, allowed_origin_ip FROM api_users"
	var rows *sql.Rows
	var err error
	if groupFilter != "" && groupFilter != "all" {
		rows, err = db.Query(query+" WHERE assigned_group = ?", groupFilter)
	} else {
		rows, err = db.Query(query)
	}
	if err != nil {
		return []UserData{}
	}
	defer rows.Close()
	var list []UserData
	for rows.Next() {
		var u UserData
		rows.Scan(&u.Username, &u.AccessKey, &u.Group, &u.IP)
		list = append(list, u)
	}
	return list
}

func addUser(user, key, group, ip string) {
	if ip == "" {
		ip = "*"
	}
	createGroup(group)
	db.Exec("INSERT OR REPLACE INTO api_users (username, access_key, assigned_group, allowed_origin_ip) VALUES (?, ?, ?, ?)", user, key, group, ip)
}

func deleteUser(username string) {
	db.Exec("DELETE FROM api_users WHERE username = ?", username)
}

func authenticateUser(user, key, originIP string) (string, bool) {
	var storedKey, assignedGroup, allowedIP string
	err := db.QueryRow("SELECT access_key, assigned_group, allowed_origin_ip FROM api_users WHERE username = ?", user).Scan(&storedKey, &assignedGroup, &allowedIP)
	if err != nil || storedKey != key {
		return "", false
	}
	if allowedIP != "*" && allowedIP != originIP {
		return "", false
	}

	var status string
	err = db.QueryRow("SELECT status FROM groups WHERE name = ?", assignedGroup).Scan(&status)
	if err == nil && status == "inactive" {
		return "", false
	}
	return assignedGroup, true
}
