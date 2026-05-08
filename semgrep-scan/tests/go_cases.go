// Test fixtures for semgrep-scan/rules/go.yml.
//
// Lines marked `// ruleid: <id>` MUST match that rule.
// Lines marked `// ok: <id>` MUST NOT match that rule.
//
// This file is never compiled; only Semgrep parses it.

package fixtures

import (
	"crypto/des"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/tls"
	cryptorand "crypto/rand"
	"database/sql"
	mathrand "math/rand"
)

// --------------------------------------------------------------------
// go-tls-insecure-skip-verify
// --------------------------------------------------------------------

func tlsBad() *tls.Config {
	// ruleid: go-tls-insecure-skip-verify
	return &tls.Config{
		ServerName:         "api.example.com",
		InsecureSkipVerify: true,
	}
}

func tlsBadValue() tls.Config {
	// ruleid: go-tls-insecure-skip-verify
	return tls.Config{
		InsecureSkipVerify: true,
	}
}

func tlsOk() *tls.Config {
	// ok: go-tls-insecure-skip-verify
	return &tls.Config{
		ServerName: "api.example.com",
	}
}

// --------------------------------------------------------------------
// go-math-rand-for-security
// --------------------------------------------------------------------

func randomToken() string {
	// ruleid: go-math-rand-for-security
	token := mathrand.Int63()
	_ = token
	return ""
}

func randomSecretAssign() {
	var secret int64
	// ruleid: go-math-rand-for-security
	secret = mathrand.Int63()
	_ = secret
}

// Cryptographically secure source — must NOT match.
func secureToken() {
	var token [32]byte
	// ok: go-math-rand-for-security
	_, _ = cryptorand.Read(token[:])
}

// Variable name doesn't suggest security usage — must NOT match.
func nonSecurityRandom() int {
	// ok: go-math-rand-for-security
	jitter := mathrand.Intn(1000)
	return jitter
}

// crypto/rand sometimes imported as the default `rand` alias —
// `token, _ := rand.Int(rand.Reader, max)` is the SECURE pattern,
// must NOT match. The math-rand-import gate prevents the FP.
// (Negative test for codex P2.)

// --------------------------------------------------------------------
// go-sql-query-string-concat
// --------------------------------------------------------------------

func sqlBad(db *sql.DB, name string) {
	// ruleid: go-sql-query-string-concat
	_, _ = db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}

func sqlBadExec(db *sql.DB, id string) {
	// ruleid: go-sql-query-string-concat
	_, _ = db.Exec("DELETE FROM users WHERE id = " + id)
}

func sqlGood(db *sql.DB, name string) {
	// ok: go-sql-query-string-concat
	_, _ = db.Query("SELECT * FROM users WHERE name = $1", name)
}

// Splitting a long SQL string across two literals for readability is
// benign — neither operand is attacker-controlled. Negative test for
// codex P2.
func sqlLongLiteral(db *sql.DB) {
	// ok: go-sql-query-string-concat
	_, _ = db.Query("SELECT a, b, c " + "FROM long_table_name WHERE x IS NOT NULL")
	// ok: go-sql-query-string-concat
	_, _ = db.Exec("UPDATE foo SET y = 1 " + "WHERE z = 2")
}

// --------------------------------------------------------------------
// go-rsa-weak-key-size
// --------------------------------------------------------------------

func rsaWeak() {
	// ruleid: go-rsa-weak-key-size
	_, _ = rsa.GenerateKey(cryptorand.Reader, 1024)
	// ruleid: go-rsa-weak-key-size
	_, _ = rsa.GenerateKey(cryptorand.Reader, 512)
}

func rsaOk() {
	// ok: go-rsa-weak-key-size
	_, _ = rsa.GenerateKey(cryptorand.Reader, 2048)
	// ok: go-rsa-weak-key-size
	_, _ = rsa.GenerateKey(cryptorand.Reader, 3072)
}

// --------------------------------------------------------------------
// go-deprecated-cipher
// --------------------------------------------------------------------

func deprecatedCiphers() {
	key := []byte("12345678")
	// ruleid: go-deprecated-cipher
	_, _ = des.NewCipher(key)
	// ruleid: go-deprecated-cipher
	_, _ = des.NewTripleDESCipher(append(key, key...))
	// ruleid: go-deprecated-cipher
	_, _ = rc4.NewCipher(key)
}
