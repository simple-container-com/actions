// Test fixtures for semgrep-scan/rules/go-canon.yml.
//
// Lines marked `// ruleid: <id>` MUST match that rule.
// Lines marked `// ok: <id>` MUST NOT match that rule.
//
// This file is never compiled; only Semgrep parses it. The `jwt` qualifier
// is unresolved on purpose — go/parser accepts it as a selector expression.

package canonfixtures

import (
	"bytes"
	"crypto/cipher"
	"crypto/tls"
	"net/http"
	"os/exec"
	"time"
)

// --------------------------------------------------------------------
// go-hmac-not-constant-time
// --------------------------------------------------------------------

func hmacBytesEqual(mac, expected []byte) bool {
	// ruleid: go-hmac-not-constant-time
	return bytes.Equal(mac, expected)
}

func sigBytesEqual(signature, expected []byte) bool {
	// ruleid: go-hmac-not-constant-time
	return bytes.Equal(signature, expected)
}

func tagBytesEqual(tag, expected []byte) bool {
	// ruleid: go-hmac-not-constant-time
	return bytes.Equal(tag, expected)
}

// Generic bytes — variable name doesn't suggest MAC/sig → must NOT fire.
func payloadEqual(a, b []byte) bool {
	// ok: go-hmac-not-constant-time
	return bytes.Equal(a, b)
}

// --------------------------------------------------------------------
// go-cipher-deterministic-nonce
// --------------------------------------------------------------------
// Positive case only — the multi-stmt `make + Seal` pattern has an
// inherent FP for `make + rand.Read(nonce) + Seal`. The rule catches the
// actually-vulnerable shape where the freshly-made nonce is never
// randomized; pairing it with a negative test in this file would itself
// fire because of that FP. Negative coverage is handled by NOT writing
// surrounding fixture shapes that match.

func aeadZeroNonce(aead cipher.AEAD, plaintext []byte) []byte {
	// ruleid: go-cipher-deterministic-nonce
	nonce := make([]byte, aead.NonceSize())
	return aead.Seal(nil, nonce, plaintext, nil)
}

// --------------------------------------------------------------------
// go-jwt-parse-unverified
// --------------------------------------------------------------------

func jwtUnverifiedBareCall(tokenString string) {
	// ruleid: go-jwt-parse-unverified
	_, _, _ = jwt.ParseUnverified(tokenString, jwt.MapClaims{})
}

func jwtUnverifiedMethodCall(p *jwt.Parser, tokenString string) {
	// ruleid: go-jwt-parse-unverified
	_, _, _ = p.ParseUnverified(tokenString, jwt.MapClaims{})
}

// `jwt.Parse` (the verified call) → must NOT fire.
func jwtVerifiedCall(tokenString string) {
	// ok: go-jwt-parse-unverified
	_, _ = jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) { return nil, nil })
}

// --------------------------------------------------------------------
// go-jwt-none-algorithm
// --------------------------------------------------------------------

// ruleid: go-jwt-none-algorithm
var _ = jwt.SigningMethodNone

// ruleid: go-jwt-none-algorithm
var _ = jwt.SigningMethodHSNone

// Literal JWT header — second regex variant.
// ruleid: go-jwt-none-algorithm
const jwtHeaderNone = `{"alg": "none", "typ": "JWT"}`

// Acceptable signing method → must NOT fire.
// ok: go-jwt-none-algorithm
var _ = jwt.SigningMethodHS256

// --------------------------------------------------------------------
// go-http-client-no-timeout
// --------------------------------------------------------------------

func httpClientNoTimeout() *http.Client {
	// ruleid: go-http-client-no-timeout
	return &http.Client{}
}

func httpClientNoTimeoutWithTransport() *http.Client {
	// ruleid: go-http-client-no-timeout
	return &http.Client{Transport: http.DefaultTransport}
}

func httpClientWithTimeout() *http.Client {
	// ok: go-http-client-no-timeout
	return &http.Client{Timeout: 30 * time.Second}
}

func httpClientWithTimeoutAndTransport() *http.Client {
	// ok: go-http-client-no-timeout
	return &http.Client{Timeout: 5 * time.Second, Transport: http.DefaultTransport}
}

// --------------------------------------------------------------------
// go-tls-min-version-below-1-2
// --------------------------------------------------------------------

func tlsConfigVersion10() *tls.Config {
	// ruleid: go-tls-min-version-below-1-2
	return &tls.Config{MinVersion: tls.VersionTLS10}
}

func tlsConfigVersion11() *tls.Config {
	// ruleid: go-tls-min-version-below-1-2
	return &tls.Config{MinVersion: tls.VersionTLS11}
}

func tlsConfigVersionHex10() *tls.Config {
	// ruleid: go-tls-min-version-below-1-2
	return &tls.Config{MinVersion: 0x0301}
}

func tlsConfigVersion12() *tls.Config {
	// ok: go-tls-min-version-below-1-2
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func tlsConfigVersion13() *tls.Config {
	// ok: go-tls-min-version-below-1-2
	return &tls.Config{MinVersion: tls.VersionTLS13}
}

// --------------------------------------------------------------------
// go-exec-command-inherits-environ-default
// --------------------------------------------------------------------

func execUntrustedRun() {
	// Untrusted binary path, no Env override → fire.
	// ruleid: go-exec-command-inherits-environ-default
	cmd := exec.Command("/opt/risky/scanner", "--scan")
	_ = cmd.Run()
}

func execUntrustedOutput() {
	// Same shape, `.Output()` form.
	// ruleid: go-exec-command-inherits-environ-default
	cmd := exec.Command("/opt/risky/scanner", "--report")
	_, _ = cmd.Output()
}

func execTrustedGit() {
	// Trusted CLI (git) → must NOT fire.
	// ok: go-exec-command-inherits-environ-default
	cmd := exec.Command("git", "status")
	_ = cmd.Run()
}

func execTrustedCosign() {
	// Trusted CLI (cosign) → must NOT fire.
	// ok: go-exec-command-inherits-environ-default
	cmd := exec.Command("cosign", "verify", "image")
	_, _ = cmd.Output()
}

func execUntrustedWithEnvSet() {
	// Untrusted binary but Env explicitly set → must NOT fire.
	// ok: go-exec-command-inherits-environ-default
	cmd := exec.Command("/opt/risky/scanner", "--scan")
	cmd.Env = []string{"PATH=/usr/bin"}
	_ = cmd.Run()
}
