# NanoTDF & TDF SDK Internals

This note reverse-engineers the OpenTDF SDK implementation for NanoTDF and full TDF files. It summarises the control flow, key data structures, and integration points in `platform/sdk`, so new contributors can navigate the code base quickly.

## NanoTDF Pipeline
- **Configuration entry** – `SDK.NewNanoTDFConfig` seeds defaults (P-256 curve, AES-GCM 96-bit tags, encrypted policies) and returns a mutable `NanoTDFConfig` (`platform/sdk/nanotdf_config.go:16`). Callers set the KAS URL, attributes, optional ECDSA policy bindings, or enable collection mode before passing it to `CreateNanoTDF`.
- **Header layout** – `NanoTDFHeader` stores the KAS locator, binding/signature modes, policy block, and uncompressed ephemeral EC public key (`platform/sdk/nanotdf.go:60`). `NewNanoTDFHeaderFromReader` streams a header from disk, validating magic bytes (`"L1L"`), ECC mode, policy encoding, and either GMAC or ECDSA bindings.
- **Policy handling** – Only plaintext and encrypted embedded policies are supported (`platform/sdk/nanotdf_policy.go:20`); remote and policy-key-access modes still return errors via `validNanoTDFPolicyMode`. `createNanoTDFEmbeddedPolicy` encrypts the on-disk policy with the session key when the config demands it.
- **Encryption flow** – `SDK.CreateNanoTDF` buffers the payload, enforces the 16 MiB limit, fetches the target KAS public key, writes the header, and AES-GCM encrypts the payload with a non-zero IV (`platform/sdk/nanotdf.go:773`). Collection mode reuses the IV slot to encode an iteration counter instead of random bytes.
- **Decryption flow** – `NanoTDFDecryptHandler` reconstructs the header, enforces optional KAS allowlists, and builds an unsigned rewrap request using the captured header bytes (`platform/sdk/nanotdf.go:830`). After the KAS returns a symmetric key, it decrypts the payload with the stored cipher parameters and verifies policy bindings through `VerifyPolicyBinding`.

## TDF Pipeline
- **Configuration entry** – `newTDFConfig` initialises defaults such as 2 MiB segment size, JSON manifest, HS256 integrity, and auto-configuration toggles (`platform/sdk/tdf_config.go:22`). Options append attribute FQNs, plug in explicit `KASInfo`, override segment sizes, or pre-generate split plans.
- **Manifest preparation** – `prepareManifest` builds the policy, splits symmetric keys per KAS, wraps them with RSA or EC, and generates policy bindings plus optional encrypted metadata (`platform/sdk/tdf.go:473`). The XOR of all symmetric shares becomes the payload key and drives the AES-GCM encryptor.
- **Payload packaging** – `CreateTDFContext` validates input size (≤ 64 GiB), initialises the KAO template, chooses a segment size, and streams encrypted segments through `archive.NewTDFWriter` (`platform/sdk/tdf.go:171`). Each segment adds IV and tag overhead to the manifest’s integrity table.
- **Decryption flow** – `SDK.LoadTDF` opens the archive, validates schema (optional strict/lax), and collects segment metadata (`platform/sdk/tdf.go:710`). `Reader.Init` orchestrates unwrap requests to the KAS, while `tdf3DecryptHandler` wires the reader into the higher-level decrypt CLI path.

## KAS & Key Management Hooks
- **Key access generation** leverages `createKeyAccess`, `generateWrapKeyWithRSA`, and `generateWrapKeyWithEC` to wrap symmetric shares for each KAS (`platform/sdk/tdf.go:585`). EC wrapping derives a HKDF session key from an ephemeral/key-server ECDH exchange.
- **Allowlisting** applies to both formats. NanoTDF uses `NanoTDFReaderConfig` and `AllowList` checks (`platform/sdk/nanotdf_config.go:63`); full TDF readers auto-populate the list from the platform registry when the client SDK has connectivity (`platform/sdk/tdf.go:666`).
- **Policy data model** – attribute FQNs expand via `NewAttributeValueFQN` and become manifest `policy.Body.DataAttributes`. The same helper types serve NanoTDF embedded policies and full TDF manifests, keeping authorisation semantics aligned.

## Helpful Entry Points
- Unit tests in `platform/sdk/nanotdf_test.go` and `platform/sdk/tdf_test.go` demonstrate end-to-end encryption/decryption and are the quickest way to replicate behaviour under a debugger.
- For service-side key handling, inspect `platform/service/internal/security/standard_crypto.go`, which loads RSA and EC key pairs referenced by the SDK when producing KAO entries.

Use this map to jump to the relevant structs and helper functions when extending NanoTDF or standard TDF behaviour (e.g. adding new policy modes, curves, or metadata assertions).
