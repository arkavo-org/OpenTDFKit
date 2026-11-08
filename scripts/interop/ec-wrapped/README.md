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

The keys in the fixture are generated for the test and protect nothing.
