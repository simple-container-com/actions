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
	"crypto/hmac"
	"crypto/md5"
	"crypto/tls"
	"net"
	"net/http"
	"os/exec"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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

// --------------------------------------------------------------------
// go-md5-in-crypto-context
// --------------------------------------------------------------------
// Fires only when MD5 is used in a cryptographic context — HMAC
// construction, or a variable whose name suggests integrity/auth.
// Non-cryptographic fingerprint uses (checksum, etag, fingerprint,
// cache-buster, annotation hash, content-addressed key) are NOT
// flagged here; the broad gosec `use-of-md5` rule that fires on those
// is disabled at the consumer level.

func md5InsideHmac(key []byte) {
	// MD5 fed into hmac.New — bona fide cryptographic use, MD5 is the
	// wrong primitive. SHOULD fire.
	// ruleid: go-md5-in-crypto-context
	_ = hmac.New(md5.New, key)
}

func md5AsMACVariable() {
	// Variable name `mac` says this is a Message Authentication Code.
	// SHOULD fire.
	// ruleid: go-md5-in-crypto-context
	mac := md5.New()
	_ = mac
}

func md5AsSignatureSum(content []byte) [16]byte {
	// Variable name `signature` says this is a signing primitive.
	// SHOULD fire.
	// ruleid: go-md5-in-crypto-context
	signature := md5.Sum(content)
	return signature
}

func md5AsPasswordSum(pw []byte) [16]byte {
	// Variable name `password` says this is password hashing — also wrong.
	// SHOULD fire.
	// ruleid: go-md5-in-crypto-context
	password := md5.Sum(pw)
	return password
}

func md5AsChecksum(content []byte) [16]byte {
	// Non-cryptographic content fingerprint. MUST NOT fire — that's the
	// whole reason we ship this narrower rule.
	// ok: go-md5-in-crypto-context
	checksum := md5.Sum(content)
	return checksum
}

func md5AsEtag(content []byte) [16]byte {
	// S3 etag-style content addressing. MUST NOT fire.
	// ok: go-md5-in-crypto-context
	etag := md5.Sum(content)
	return etag
}

func md5AsAnnotationHash(caddyfile []byte) [16]byte {
	// Kubernetes annotation value for change detection (used by SC's
	// Caddy-update-hash annotation). MUST NOT fire.
	// ok: go-md5-in-crypto-context
	hashBytes := md5.Sum(caddyfile)
	return hashBytes
}

func md5SumInExpression(content []byte) [16]byte {
	// `md5.Sum(...)` used inline — no variable name to inspect → no fire.
	// MUST NOT fire.
	// ok: go-md5-in-crypto-context
	return md5.Sum(content)
}

// --------------------------------------------------------------------
// go-grpc-server-plaintext-non-loopback
// --------------------------------------------------------------------

func grpcLoopbackServer() {
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	// ok: go-grpc-server-plaintext-non-loopback
	srv := grpc.NewServer()
	_ = srv.Serve(lis)
}

func grpcLocalhostServer() error {
	lis, _ := net.Listen("tcp", "localhost:9000")
	// ok: go-grpc-server-plaintext-non-loopback
	srv := grpc.NewServer()
	return srv.Serve(lis)
}

func grpcUnixServer() error {
	lis, _ := net.Listen("unix", "/tmp/x.sock")
	// ok: go-grpc-server-plaintext-non-loopback
	srv := grpc.NewServer()
	return srv.Serve(lis)
}

func grpcServerWithCreds(creds credentials.TransportCredentials) error {
	lis, _ := net.Listen("tcp", ":8443")
	// ok: go-grpc-server-plaintext-non-loopback
	srv := grpc.NewServer(grpc.Creds(creds))
	return srv.Serve(lis)
}

func grpcServerWithCredsAndOpts(creds credentials.TransportCredentials) error {
	lis, _ := net.Listen("tcp", ":8443")
	// ok: go-grpc-server-plaintext-non-loopback
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(1<<20), grpc.Creds(creds))
	return srv.Serve(lis)
}

func grpcWildcardServer() error {
	lis, _ := net.Listen("tcp", ":50051")
	// ruleid: go-grpc-server-plaintext-non-loopback
	srv := grpc.NewServer()
	return srv.Serve(lis)
}

func grpcAllInterfacesServer() error {
	lis, _ := net.Listen("tcp", "0.0.0.0:50051")
	// ruleid: go-grpc-server-plaintext-non-loopback
	srv := grpc.NewServer()
	return srv.Serve(lis)
}

func grpcLookalikeHostServer() error {
	lis, _ := net.Listen("tcp", "127.0.0.1.evil.example:50051")
	// ruleid: go-grpc-server-plaintext-non-loopback
	srv := grpc.NewServer()
	return srv.Serve(lis)
}

func grpcServerFromArgListener(lis net.Listener) error {
	// ruleid: go-grpc-server-plaintext-non-loopback
	srv := grpc.NewServer()
	return srv.Serve(lis)
}

func grpcLoopbackNamedOnlyInIfElse(public bool) error {
	var lis net.Listener
	if public {
		lis, _ = net.Listen("tcp", ":50051")
	} else {
		lis, _ = net.Listen("tcp", "127.0.0.1:0")
	}
	// Known limit (documented in the rule): a loopback Listen anywhere in the
	// function exempts it, even if another branch binds a public address.
	// ok: go-grpc-server-plaintext-non-loopback
	srv := grpc.NewServer()
	return srv.Serve(lis)
}

func grpcServerCallerSuppliedOpts(opts []grpc.ServerOption) *grpc.Server {
	// ok: go-grpc-server-plaintext-non-loopback
	return grpc.NewServer(opts...)
}
