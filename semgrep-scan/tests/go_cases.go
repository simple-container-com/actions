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
	"fmt"
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

// Bare-value `tls.Config{...}` (never addressed) is vanishingly rare
// in practice and the bare-form pattern was producing duplicate findings
// on `&tls.Config{...}` (codex P3). Rule scope was narrowed to the
// pointer form only; this is now a negative test.
func tlsBareValue() tls.Config {
	// ok: go-tls-insecure-skip-verify
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

// --------------------------------------------------------------------
// go-aws-rds-no-storage-encryption
// --------------------------------------------------------------------
//
// Surrogate types matching the shape of the pulumi-aws-sdk so the
// AST patterns line up. Semgrep doesn't compile the file — only the
// surface syntax matters.

type pulumiCtx struct{}

type instanceArgs struct {
	Engine           string
	StorageEncrypted bool
	AllocatedStorage int
}

type clusterArgs struct {
	Engine           string
	StorageEncrypted bool
}

var rds = struct {
	NewInstance func(*pulumiCtx, string, *instanceArgs) error
	NewCluster  func(*pulumiCtx, string, *clusterArgs) error
}{
	NewInstance: func(_ *pulumiCtx, _ string, _ *instanceArgs) error { return nil },
	NewCluster:  func(_ *pulumiCtx, _ string, _ *clusterArgs) error { return nil },
}

func rdsBad(ctx *pulumiCtx) {
	// ruleid: go-aws-rds-no-storage-encryption
	_ = rds.NewInstance(ctx, "db1", &instanceArgs{
		Engine:           "postgres",
		AllocatedStorage: 20,
	})
}

func rdsBadCluster(ctx *pulumiCtx) {
	// ruleid: go-aws-rds-no-storage-encryption
	_ = rds.NewCluster(ctx, "cluster1", &clusterArgs{
		Engine: "aurora-postgresql",
	})
}

func rdsOk(ctx *pulumiCtx) {
	// ok: go-aws-rds-no-storage-encryption
	_ = rds.NewInstance(ctx, "db2", &instanceArgs{
		Engine:           "postgres",
		StorageEncrypted: true,
		AllocatedStorage: 20,
	})
}

func rdsOkCluster(ctx *pulumiCtx) {
	// ok: go-aws-rds-no-storage-encryption
	_ = rds.NewCluster(ctx, "cluster2", &clusterArgs{
		Engine:           "aurora-postgresql",
		StorageEncrypted: true,
	})
}

// Codex P2: explicitly setting `StorageEncrypted: false` (or
// `pulumi.Bool(false)`) must STILL fire — the field name being
// present isn't enough. Both forms of the bare-bool value are
// covered below.
func rdsExplicitlyDisabledBool(ctx *pulumiCtx) {
	// ruleid: go-aws-rds-no-storage-encryption
	_ = rds.NewInstance(ctx, "db3", &instanceArgs{
		Engine:           "postgres",
		StorageEncrypted: false,
	})
}

// Runtime-config secure-by-default shape:
// `<ptr>.Bool(lo.FromPtrOr(<*bool>, true))`. Used in
// simple-container-com/api: nil → true (encrypted), explicit value
// otherwise. Paired with `IgnoreChanges([]string{"storageEncrypted"})`
// on the resource opts (not shown — pairing isn't regex-verified).
// Must NOT fire.
type pulumiSdk struct{}

func (pulumiSdk) Bool(_ bool) bool { return false }

var sdk = pulumiSdk{}
var pulumi = pulumiSdk{}

type loPkg struct{}

func (loPkg) FromPtr(_ *bool) bool             { return false }
func (loPkg) FromPtrOr(_ *bool, _ bool) bool   { return false }

var lo = loPkg{}

type dbConfigShape struct{ StorageEncrypted *bool }

func rdsRuntimeSecureSdk(ctx *pulumiCtx) {
	cfg := dbConfigShape{}
	// ok: go-aws-rds-no-storage-encryption
	_ = rds.NewInstance(ctx, "db4", &instanceArgs{
		Engine:           "postgres",
		StorageEncrypted: sdk.Bool(lo.FromPtrOr(cfg.StorageEncrypted, true)),
	})
}

// Same shape with `pulumi.Bool` prefix — must also NOT fire.
func rdsRuntimeSecurePulumi(ctx *pulumiCtx) {
	cfg := dbConfigShape{}
	// ok: go-aws-rds-no-storage-encryption
	_ = rds.NewCluster(ctx, "cluster3", &clusterArgs{
		Engine:           "aurora-postgresql",
		StorageEncrypted: pulumi.Bool(lo.FromPtrOr(cfg.StorageEncrypted, true)),
	})
}

// Bare `lo.FromPtr(*ptr)` defaults to false when nil — DB ends up
// unencrypted-by-default. Must STILL FIRE.
func rdsBareFromPtrStillFires(ctx *pulumiCtx) {
	cfg := dbConfigShape{}
	// ruleid: go-aws-rds-no-storage-encryption
	_ = rds.NewInstance(ctx, "db5", &instanceArgs{
		Engine:           "postgres",
		StorageEncrypted: sdk.Bool(lo.FromPtr(cfg.StorageEncrypted)),
	})
}

// `lo.FromPtrOr(*ptr, false)` is just bare-FromPtr in disguise — the
// fallback is unencrypted, so the DB defaults to unencrypted. Must
// STILL FIRE.
func rdsFromPtrOrFalseStillFires(ctx *pulumiCtx) {
	cfg := dbConfigShape{}
	// ruleid: go-aws-rds-no-storage-encryption
	_ = rds.NewInstance(ctx, "db6", &instanceArgs{
		Engine:           "postgres",
		StorageEncrypted: sdk.Bool(lo.FromPtrOr(cfg.StorageEncrypted, false)),
	})
}

// Arbitrary wrapper that isn't the recognized helper — rule must
// FIRE (we don't trust unknown runtime expressions).
func rdsArbitraryWrapperStillFires(ctx *pulumiCtx) {
	// ruleid: go-aws-rds-no-storage-encryption
	_ = rds.NewInstance(ctx, "db7", &instanceArgs{
		Engine:           "postgres",
		StorageEncrypted: sdk.Bool(someRuntimeBool()),
	})
}

func someRuntimeBool() bool { return false }

// --------------------------------------------------------------------
// go-fmt-errorf-percent-v-for-error
// --------------------------------------------------------------------

func errfBadEnd(err error) error {
	// ruleid: go-fmt-errorf-percent-v-for-error
	return fmt.Errorf("failed to read: %v", err)
}

func errfBadCustomName(myErr error) error {
	// ruleid: go-fmt-errorf-percent-v-for-error
	return fmt.Errorf("downstream call: %v", myErr)
}

func errfBadCapitalised(readErr error) error {
	// ruleid: go-fmt-errorf-percent-v-for-error
	return fmt.Errorf("read: %v", readErr)
}

func errfOkPercentW(err error) error {
	// ok: go-fmt-errorf-percent-v-for-error
	return fmt.Errorf("failed to read: %w", err)
}

// `%v` is fine for non-error values; only the error-shaped trailing
// arg is the antipattern. Negative test.
func errfOkNonError(n int) error {
	// ok: go-fmt-errorf-percent-v-for-error
	return fmt.Errorf("invalid count: %v", n)
}

// Mixed `%v ... %w` — the LAST verb is `%w`, so the error IS wrapped.
// Current rule keys off `%v"$` (string ends with %v) so this pattern
// is not flagged. Negative test.
func errfMixedVW(err error) error {
	// ok: go-fmt-errorf-percent-v-for-error
	return fmt.Errorf("ctx %v failed: %w", "details", err)
}
