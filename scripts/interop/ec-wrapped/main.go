// Command ec-wrapped checks OpenTDFKit's TDF `ec-wrapped` key access objects
// against the go reference implementation (github.com/opentdf/platform).
//
//	go run . generate        print a fixture produced the way go writes it
//
// generate mirrors sdk/tdf.go generateWrapKeyWithEC for the key access object
// and service/kas/access/rewrap.go for the rewrap response, using the same
// lib/ocrypto calls. The policy binding is the spec form, Base64 of the raw
// HMAC-SHA256, not go's legacy hex form, which OpenTDFKit refuses.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ec-wrapped generate")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "generate":
		out := must(json.MarshalIndent(generate(), "", "  "))
		fmt.Println(string(out))
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		os.Exit(2)
	}
}
