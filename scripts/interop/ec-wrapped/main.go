// Command ec-wrapped checks OpenTDFKit's TDF `ec-wrapped` key access objects
// against the go reference implementation (github.com/opentdf/platform).
//
//	go run . generate        print a fixture produced the way go writes it
//	go run . verify <path>   open a fixture written by OpenTDFKit the way go does
//
// generate mirrors sdk/tdf.go generateWrapKeyWithEC for the key access object
// and service/kas/access/rewrap.go for the rewrap response, using the same
// lib/ocrypto calls. The policy binding is the spec form, Base64 of the raw
// HMAC-SHA256, not go's legacy hex form, which OpenTDFKit refuses.
//
// verify reads the same JSON shape, written by OpenTDFKit's
// TDFKASEncryptorTests.testWriteSwiftFixtureForGo. It opens the key access
// object the way the platform KAS does (PEM-decode the ephemeral key, PKIX
// parse, compress, NewSaltedECDecryptor with the TDF salt), checks the
// spec-form policy binding, and opens the rewrap response the way the go SDK
// client does (ComputeECDHKey, CalculateHKDF with the TDF salt, AES-GCM).
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/opentdf/platform/lib/ocrypto"
)

// tdfSalt is the go SDK's tdfSalt(): SHA256("TDF").
func tdfSalt() []byte {
	digest := sha256.Sum256([]byte("TDF"))
	return digest[:]
}

type policyBinding struct {
	Alg  string `json:"alg"`
	Hash string `json:"hash"`
}

type keyAccess struct {
	Type               string        `json:"type"`
	URL                string        `json:"url"`
	Protocol           string        `json:"protocol"`
	WrappedKey         string        `json:"wrappedKey"`
	PolicyBinding      policyBinding `json:"policyBinding"`
	Kid                string        `json:"kid"`
	SchemaVersion      string        `json:"schemaVersion"`
	EphemeralPublicKey string        `json:"ephemeralPublicKey"`
}

type response struct {
	WrappedKeyBase64    string `json:"wrappedKeyBase64"`
	SessionPublicKeyPEM string `json:"sessionPublicKeyPEM"`
}

type fixture struct {
	KASPrivateKeyPEM      string    `json:"kasPrivateKeyPEM"`
	PolicyBase64          string    `json:"policyBase64"`
	KAO                   keyAccess `json:"kao"`
	DEKBase64             string    `json:"dekBase64"`
	ReceiverPrivateKeyPEM string    `json:"receiverPrivateKeyPEM"`
	Response              response  `json:"response"`
}

func must[T any](v T, err error) T {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	return v
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	must(rand.Read(b))
	return b
}

func generate() fixture {
	kas := must(ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1))
	kasPublicPEM := must(kas.PublicKeyInPemFormat())
	dek := randomBytes(32)

	policyJSON := fmt.Sprintf(`{"uuid":"%s","body":{"dataAttributes":[],"dissem":["interop@example.com"]}}`,
		hex.EncodeToString(randomBytes(16)))
	policyBase64 := base64.StdEncoding.EncodeToString([]byte(policyJSON))

	// Key access object: sdk/tdf.go generateWrapKeyWithEC.
	ephemeral := must(ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1))
	ephemeralPublicPEM := must(ephemeral.PublicKeyInPemFormat())
	ephemeralPrivatePEM := must(ephemeral.PrivateKeyInPemFormat())
	ecdhKey := must(ocrypto.ComputeECDHKey([]byte(ephemeralPrivatePEM), []byte(kasPublicPEM)))
	sessionKey := must(ocrypto.CalculateHKDF(tdfSalt(), ecdhKey))
	gcm := must(ocrypto.NewAESGcm(sessionKey))
	wrapped := must(gcm.Encrypt(dek))

	mac := hmac.New(sha256.New, dek)
	mac.Write([]byte(policyBase64))

	// Rewrap response: service/kas/access/rewrap.go.
	receiver := must(ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1))
	receiverPublicPEM := must(receiver.PublicKeyInPemFormat())
	encryptor := must(ocrypto.FromPublicPEMWithSalt(receiverPublicPEM, tdfSalt(), nil))
	sessionPublicPEM := must(encryptor.PublicKeyInPemFormat())
	rewrapped := must(encryptor.Encrypt(dek))

	return fixture{
		KASPrivateKeyPEM: must(kas.PrivateKeyInPemFormat()),
		PolicyBase64:     policyBase64,
		KAO: keyAccess{
			Type:               "ec-wrapped",
			URL:                "https://kas.example.com",
			Protocol:           "kas",
			WrappedKey:         base64.StdEncoding.EncodeToString(wrapped),
			PolicyBinding:      policyBinding{Alg: "HS256", Hash: base64.StdEncoding.EncodeToString(mac.Sum(nil))},
			Kid:                "e1",
			SchemaVersion:      "1.0",
			EphemeralPublicKey: ephemeralPublicPEM,
		},
		DEKBase64:             base64.StdEncoding.EncodeToString(dek),
		ReceiverPrivateKeyPEM: must(receiver.PrivateKeyInPemFormat()),
		Response: response{
			WrappedKeyBase64:    base64.StdEncoding.EncodeToString(rewrapped),
			SessionPublicKeyPEM: sessionPublicPEM,
		},
	}
}

func verify(path string) error {
	var f fixture
	if err := json.Unmarshal(must(os.ReadFile(path)), &f); err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	return verifyFixture(f)
}

func verifyFixture(f fixture) error {
	dek, err := base64.StdEncoding.DecodeString(f.DEKBase64)
	if err != nil {
		return fmt.Errorf("dekBase64: %w", err)
	}
	if f.KAO.Type != "ec-wrapped" {
		return fmt.Errorf("kao type is %q, want ec-wrapped", f.KAO.Type)
	}
	if f.KAO.Kid == "" {
		return errors.New("kao has no kid; a platform KAS finds EC keys by kid")
	}
	// Field spellings: a writer whose JSON keys differ from go's tags leaves these empty.
	if f.KAO.URL == "" {
		return errors.New("kao has no url")
	}
	if f.KAO.Protocol != "kas" {
		return fmt.Errorf("kao protocol is %q, want kas", f.KAO.Protocol)
	}
	if f.KAO.SchemaVersion == "" {
		return errors.New("kao has no schemaVersion")
	}

	// Key access object, as service/kas/access/rewrap.go case "ec-wrapped".
	if _, err := ocrypto.GetECKeySize([]byte(f.KAO.EphemeralPublicKey)); err != nil {
		return fmt.Errorf("ephemeral key size: %w", err)
	}
	block, _ := pem.Decode([]byte(f.KAO.EphemeralPublicKey))
	if block == nil {
		return errors.New("ephemeral public key is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("ephemeral public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("ephemeral key is not EC")
	}
	compressed, err := ocrypto.CompressedECPublicKey(ocrypto.ECCModeSecp256r1, *ecPub)
	if err != nil {
		return fmt.Errorf("compress ephemeral key: %w", err)
	}
	kasKey, err := ocrypto.ECPrivateKeyFromPem([]byte(f.KASPrivateKeyPEM))
	if err != nil {
		return fmt.Errorf("kas private key: %w", err)
	}
	decryptor, err := ocrypto.NewSaltedECDecryptor(kasKey, tdfSalt(), nil)
	if err != nil {
		return err
	}
	wrapped, err := base64.StdEncoding.DecodeString(f.KAO.WrappedKey)
	if err != nil {
		return fmt.Errorf("kao wrappedKey: %w", err)
	}
	share, err := decryptor.DecryptWithEphemeralKey(wrapped, compressed)
	if err != nil {
		return fmt.Errorf("kao unwrap: %w", err)
	}
	if !bytes.Equal(share, dek) {
		return errors.New("kao unwrapped to a different key")
	}

	// Policy binding, spec form.
	if f.KAO.PolicyBinding.Alg != "HS256" {
		return fmt.Errorf("binding alg is %q, want HS256", f.KAO.PolicyBinding.Alg)
	}
	expected, err := base64.StdEncoding.DecodeString(f.KAO.PolicyBinding.Hash)
	if err != nil || len(expected) != sha256.Size {
		return errors.New("binding hash is not base64 of a 32-byte HMAC")
	}
	mac := hmac.New(sha256.New, dek)
	mac.Write([]byte(f.PolicyBase64))
	if !hmac.Equal(mac.Sum(nil), expected) {
		return errors.New("policy binding does not verify")
	}

	// Rewrap response, as sdk/kas_client.go opens an EC session response.
	ecdhKey, err := ocrypto.ComputeECDHKey([]byte(f.ReceiverPrivateKeyPEM), []byte(f.Response.SessionPublicKeyPEM))
	if err != nil {
		return fmt.Errorf("response ECDH: %w", err)
	}
	sessionKey, err := ocrypto.CalculateHKDF(tdfSalt(), ecdhKey)
	if err != nil {
		return err
	}
	gcm, err := ocrypto.NewAESGcm(sessionKey)
	if err != nil {
		return err
	}
	rewrapped, err := base64.StdEncoding.DecodeString(f.Response.WrappedKeyBase64)
	if err != nil {
		return fmt.Errorf("response wrappedKeyBase64: %w", err)
	}
	opened, err := gcm.Decrypt(rewrapped)
	if err != nil {
		return fmt.Errorf("response unwrap: %w", err)
	}
	if !bytes.Equal(opened, dek) {
		return errors.New("response unwrapped to a different key")
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ec-wrapped generate | verify <path>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "generate":
		out := must(json.MarshalIndent(generate(), "", "  "))
		fmt.Println(string(out))
	case "verify":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: ec-wrapped verify <path>")
			os.Exit(2)
		}
		if err := verify(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL:", err)
			os.Exit(1)
		}
		fmt.Println("OK")
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		os.Exit(2)
	}
}
