# ec-wrapped interop check

Checks OpenTDFKit's TDF `ec-wrapped` key access objects and `TDFKAS` rewrap
responses against the go reference implementation, using the same
`github.com/opentdf/platform/lib/ocrypto` calls as the go SDK and the platform
KAS.

## Regenerate the go fixture (go → Swift)

```bash
cd scripts/interop/ec-wrapped
go run . generate > fixture.json
```

Paste `fixture.json` verbatim into `OpenTDFKitTests/TDFKASGoFixture.swift`
(between the `#"""` delimiters), then delete `fixture.json`. The key access
object mirrors the go SDK's `generateWrapKeyWithEC`; the response mirrors the
platform KAS's rewrap sealing. The policy binding is the spec form (Base64 of
the raw HMAC), not go's legacy hex form, which OpenTDFKit refuses.

## Verify Swift output with go (Swift → go)

Required before tagging a release that touches the EC path.

```bash
OPENTDFKIT_INTEROP_OUT="$PWD/swift-interop.json" \
  swift test --filter TDFKASEncryptorTests/testWriteSwiftFixtureForGo
(cd scripts/interop/ec-wrapped && go run . verify "$OLDPWD/swift-interop.json")
rm swift-interop.json
```

The test writes a key access object from `TDFEncryptor` and a `TDFKAS.rewrap`
response. `verify` opens the key access object the way the platform KAS does,
checks the spec-form policy binding, opens the response the way the go SDK
client does, and prints `OK`.

The keys in the fixture are generated for the test and protect nothing.
