# XTest SDK CLI Requirements

## Role of the CLI Wrapper
`xtest` drives every SDK through `sdk/<lang>/dist/<version>/cli.sh`. The wrapper may call binaries, jars, or npm CLIs, but it **must** present a uniform command surface so pytest can swap SDKs without code changes.

## Directory & Build Expectations
- Implementation sources live under `sdk/<lang>/src/<version>/`; runnable artifacts, helper binaries, and `cli.sh` belong in `sdk/<lang>/dist/<version>/`.
- `make -C sdk/<lang>` must build your CLI non-interactively (Go `go build`, Java `mvn`, JS `npm pack`, etc.) because CI invokes these targets verbatim.
- Bundle every runtime dependency (e.g. `otdfctl`, `cmdline.jar`, npm packages) beside `cli.sh`. Do not rely on globally installed tooling.
- Provide a language-specific `sdk/<lang>/Makefile` so `make -C sdk` refreshes all SDKs in one pass, as the GitHub workflow assumes.

## CLI Contract
```
./cli.sh encrypt <plaintext> <ciphertext> <nano|ztdf|ztdf-ecwrap|nano-with-ecdsa>
./cli.sh decrypt <ciphertext> <recovered> <nano|ztdf|ztdf-ecwrap|nano-with-ecdsa>
./cli.sh supports <feature>
```
- `encrypt` must produce the file named in `<ciphertext>` (no extra suffixes). `decrypt` must exit `0` only when `<recovered>` matches the original content.
- Inherit configuration from `xtest/test.env`; respect `CLIENTID`, `CLIENTSECRET`, `KASURL`, `PLATFORMURL`, and friends rather than hard-coding endpoints.
- Translate harness flags to native switches: `XT_WITH_MIME_TYPE`, `XT_WITH_ATTRIBUTES`, `XT_WITH_ASSERTIONS`, `XT_WITH_ASSERTION_VERIFICATION_KEYS`, `XT_WITH_VERIFY_ASSERTIONS`, `XT_WITH_ECDSA_BINDING`, `XT_WITH_ECWRAP`, `XT_WITH_PLAINTEXT_POLICY`, `XT_WITH_TARGET_MODE`, `XT_WITH_KAS_ALLOWLIST`, `XT_WITH_IGNORE_KAS_ALLOWLIST`. Existing wrappers also accept `XT_WITH_KAS_ALLOW_LIST`; support both spellings to stay compatible.
- Reject unsupported combinations with a clear error message and non-zero exit so pytest records the failure.

## Feature Discovery
`tdfs.SDK.supports(feature)` executes `./cli.sh supports <feature>` and treats return code `0` as "supported". Current probes include `assertions`, `assertion_verification`, `autoconfigure`, `better-messages-2024`, `bulk_rewrap`, `connectrpc`, `ecwrap`, `hexless`, `hexaflexible`, `kasallowlist`, `key_management`, `nano_attribute_bug`, `nano_ecdsa`, `nano_policymode_plaintext`, `ns_grants`. Update `tdfs.SDK._uncached_supports` if the feature is always-on for a given language to avoid unnecessary probes.

## Error Semantics
Tamper tests expect clear diagnostics mentioning integrity failures (e.g. `tamper`, `IntegrityError`, `InvalidFileError`, `signature`). Emit those before failing so pytest can assert against `subprocess.CalledProcessError.output`.

## CI Workflow Integration
- `.github/workflows/xtest.yml` runs on PRs, scheduled builds, and manual dispatch. It resolves SDK/platform refs, runs `make` in every `sdk/<lang>` directory, and then calls pytest. Keep targets headless, idempotent, and tolerant of already-present `dist/` directories.
- The workflow passes `FOCUS_SDK` (from workflow inputs) into pytest’s `--focus` option. Ensure your CLI works when other SDKs are missing or tests skip non-focused combinations.
- CI executes `pytest test_nano.py test_self.py` (harness sanity), `pytest -ra -v test_legacy.py`, core suites `test_tdfs.py` and `test_policytypes.py`, and conditionally `test_abac.py` when multi-KAS support is detected. Your CLI must honor allow-list knobs and additional KAS endpoints spun up by the workflow.
- Jobs may drop per-version environment overrides (for example `sdk/java/<tag>.env`) that `cli.sh` should auto-source. Avoid extra manual steps outside of the Makefile.

## Version Resolution & Checkout Tooling
- `sdk/scripts/resolve-version.py` maps aliases such as `main`, `latest`, `lts`, PR refs, and SHAs to concrete commits; extend it if your SDK needs extra metadata (`env` values, protocol branches, etc.).
- `sdk/scripts/checkout-sdk-branch.sh` creates or updates worktrees under `sdk/<lang>/src/<branch>`; keep repository URLs accurate and ensure new languages register here.
- `sdk/scripts/checkout-all.sh` and `cleanup-all.sh` are convenience wrappers used locally and in CI; confirm your additions remain compatible.

## Local Platform & Fixtures
- The local workflow in `xtest/README.md` provisions the platform via `docker compose`, `go run ./service` helpers, and `pip install -r requirements.txt`; validate your CLI against that flow before opening PRs.
- `PlatformFeatureSet` derives capabilities from the `PLATFORM_VERSION` env var. Set it explicitly when testing against non-default services so feature gating matches reality.
- Tests rely on canonical manifests under `xtest/golden/` and schemas in `xtest/manifest.schema.json`. Update both when your SDK introduces new container fields or policy details.

## Integration Checklist for New SDKs
1. Populate `sdk/<lang>/dist/<version>/cli.sh` plus artifacts; make the wrapper executable and self-contained.
2. Add build automation via `sdk/<lang>/Makefile` and, if needed, extend `sdk/scripts/checkout-*.sh` for source syncing.
3. Bootstrap the harness (`python -m venv`, install `xtest/requirements.txt`) and run `pytest test_tdfs.py -k <lang>` plus `pytest test_policytypes.py` locally.
4. Verify `./cli.sh supports <feature>` returns accurate exit codes and emits helpful errors when a feature is missing.
5. Document SDK-specific caveats here or in `xtest/README.md` so workflow operators and future implementors stay aligned.
