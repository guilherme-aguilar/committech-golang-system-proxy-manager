package database

import (
	"crypto/rand"
	"database/sql"
	"log"
	"math/big"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var DB *sql.DB

func Init(path string) {
	var err error
	DB, err = sql.Open("sqlite", path)
	if err != nil {
		log.Fatal(err)
	}

	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, access_key TEXT, group_name TEXT, allowed_ip TEXT);`,
		`CREATE TABLE IF NOT EXISTS tokens (group_name TEXT PRIMARY KEY, token TEXT);`,
	}
	for _, q := range queries {
		if _, err := DB.Exec(q); err != nil {
			log.Fatalf("Erro DB init: %v", err)
		}
	}
}

// --- Funções de Bootstrapping e Utils ---

func HasUsers() bool {
	var count int
	DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count > 0
}

func GenerateRandomString(n int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// --- User Management ---

func AddUser(username, plainPassword, group, ip string) error {
	hashed, err := HashPassword(plainPassword)
	if err != nil {
		return err
	}
	_, err = DB.Exec("INSERT OR REPLACE INTO users(username, access_key, group_name, allowed_ip) VALUES(?, ?, ?, ?)",
		username, hashed, group, ip)
	return err
}

func AuthenticateUser(username, plainPassword, remoteIP string) (string, bool) {
	var storedHash, group, allowedIP string
	err := DB.QueryRow("SELECT access_key, group_name, allowed_ip FROM users WHERE username = ?", username).Scan(&storedHash, &group, &allowedIP)
	if err != nil {
		return "", false
	}
	if !CheckPasswordHash(plainPassword, storedHash) {
		return "", false
	}
	if allowedIP != "*" && allowedIP != remoteIP {
		return "", false
	}
	return group, true
}

func GetAllUsers(groupFilter string) []map[string]string {
	results := make([]map[string]string, 0)
	query := "SELECT username, group_name, allowed_ip FROM users"
	var rows *sql.Rows
	var err error

	if groupFilter != "" && groupFilter != "all" {
		query += " WHERE group_name = ?"
		rows, err = DB.Query(query, groupFilter)
	} else {
		rows, err = DB.Query(query)
	}

	if err != nil {
		return results
	}
	defer rows.Close()

	for rows.Next() {
		var u, g, i string
		rows.Scan(&u, &g, &i)
		results = append(results, map[string]string{"username": u, "group": g, "ip": i})
	}
	return results
}

func DeleteUser(username string) {
	DB.Exec("DELETE FROM users WHERE username = ?", username)
}

// --- Token Management ---

func GenerateAndSetToken(group string) string {
	token, _ := HashPassword(GenerateRandomString(10) + group)
	token = token[:16]
	DB.Exec("INSERT OR REPLACE INTO tokens(group_name, token) VALUES(?, ?)", group, token)
	return token
}

func GetGroupForToken(token string) (string, bool) {
	var group string
	err := DB.QueryRow("SELECT group_name FROM tokens WHERE token = ?", token).Scan(&group)
	return group, err == nil
}

func GetAllTokens(groupFilter string) map[string]string {
	results := make(map[string]string)
	rows, err := DB.Query("SELECT group_name, token FROM tokens")
	if err != nil {
		return results
	}
	defer rows.Close()
	for rows.Next() {
		var g, t string
		rows.Scan(&g, &t)
		if groupFilter == "" || groupFilter == "all" || groupFilter == g {
			results[g] = t
		}
	}
	return results
}

func GetAllGroups() []string {
	rows, err := DB.Query("SELECT group_name FROM tokens")
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

func DeleteToken(token string) { DB.Exec("DELETE FROM tokens WHERE token = ?", token) }
func DeleteGroup(name string) {
	DB.Exec("DELETE FROM tokens WHERE group_name = ?", name)
	DB.Exec("DELETE FROM users WHERE group_name = ?", name)
}
