// Intentionally vulnerable Go code for testing SecureCodeAnalyzer.
package main

import (
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
)

// SQL Injection — fmt.Sprintf in Query
func getUser(db *sql.DB, name string) {
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE name='%s'", name))
}

// Hardcoded secrets
var password = "super_secret_go_password"
var api_key = "sk-abcdefghijklmnopqrst"

// Insecure random — math/rand already imported above
func generateToken() int {
	return rand.Intn(999999)
}

// Open redirect
func handleRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("url"), 302)
}

// Path traversal — os.Open with request data
func readFile(w http.ResponseWriter, r *http.Request) {
	f, _ := os.Open(r.URL.Query().Get("path"))
	defer f.Close()
}

// Command injection — exec.Command with request data
func runCommand(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command(r.URL.Query().Get("cmd"))
	cmd.Run()
}

// XSS — unescaped HTML in response
func renderHTML(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<div>%s</div>", r.URL.Query().Get("name"))
}
