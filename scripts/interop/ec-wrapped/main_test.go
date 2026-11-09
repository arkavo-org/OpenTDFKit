package main

import "testing"

// A fixture generate() writes the way go does must verify.
func TestVerifyAcceptsGeneratedFixture(t *testing.T) {
	if err := verifyFixture(generate()); err != nil {
		t.Fatalf("verify(generate()) = %v", err)
	}
}

// Each mutation must make verify fail. The field checks catch a writer that
// spells a key access object field differently from go's JSON tags.
func TestVerifyRejectsBadFixtures(t *testing.T) {
	tamper := func(s string) string {
		b := []byte(s)
		if b[10] == 'A' {
			b[10] = 'B'
		} else {
			b[10] = 'A'
		}
		return string(b)
	}
	cases := map[string]func(*fixture){
		"empty url":            func(f *fixture) { f.KAO.URL = "" },
		"wrong protocol":       func(f *fixture) { f.KAO.Protocol = "" },
		"empty schemaVersion":  func(f *fixture) { f.KAO.SchemaVersion = "" },
		"empty kid":            func(f *fixture) { f.KAO.Kid = "" },
		"wrong type":           func(f *fixture) { f.KAO.Type = "wrapped" },
		"tampered policy":      func(f *fixture) { f.PolicyBase64 = tamper(f.PolicyBase64) },
		"tampered binding":     func(f *fixture) { f.KAO.PolicyBinding.Hash = tamper(f.KAO.PolicyBinding.Hash) },
		"tampered wrapped key": func(f *fixture) { f.KAO.WrappedKey = tamper(f.KAO.WrappedKey) },
		"tampered response":    func(f *fixture) { f.Response.WrappedKeyBase64 = tamper(f.Response.WrappedKeyBase64) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := generate()
			mutate(&f)
			if err := verifyFixture(f); err == nil {
				t.Fatal("verify accepted a bad fixture")
			}
		})
	}
}
