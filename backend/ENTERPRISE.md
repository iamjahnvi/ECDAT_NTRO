# Enterprise discovery

## Install and run

Use Python 3.11 or newer. From `backend/`:

```sh
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-connectors.txt -r requirements-dev.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

Semgrep must be installed on the backend. Connector packages are optional if those providers are not used. The app reports unavailable dependencies and denied provider calls instead of reporting a successful empty inventory.

## Discovery inputs

Home contains Business context and Enterprise discovery controls. `POST /discover` accepts up to 100 targets, with bounded concurrency (1–8). Each target has `kind`, `target`, and optional `context`; a request-level context supplies defaults. See `discovery.example.json`.

| Kind | Target | Server configuration / read permissions |
|---|---|---|
| `materials` | Server file/directory | PEM/DER X.509, RSA, EC, DSA, DH, Ed25519/448, X25519/448; SSH public keys. Files up to 4 MB. |
| `tls` | DNS name/IP; optional `port`, `server_name` | Network reachability. Version handshakes, certificate expiry/key strength, chain/hostname verification, individually offered OpenSSL TLS ≤1.2 suites. TLS 1.3 suite enumeration is not supported by Python ssl; negotiated suite is reported. |
| `aws` | Region | boto3 credential chain (instance role, workload identity, or AWS profile). `kms:ListKeys`, `DescribeKey`, `GetKeyRotationStatus`. |
| `azure` | Key Vault HTTPS URL | DefaultAzureCredential; list/get keys and key versions. |
| `gcp` | `projects/ID/locations/LOCATION` | Application Default Credentials; list key rings, crypto keys, and versions. |
| `vault` | Vault HTTPS URL; optional `mount` | `VAULT_TOKEN`; list/read transit key metadata. No key export call is made. |
| `hsm` | PKCS#11 library path | Must match `ECDAT_PKCS11_MODULE`; optional `ECDAT_HSM_PIN`, target `token_label`. Read-only sessions; key bytes are never requested. |
| `repository` | Server-local directory, HTTPS Git URL, SSH Git URL | Existing Git credential helper / SSH agent, or `ECDAT_GIT_TOKEN` scoped to `ECDAT_GIT_HOST` (default github.com). Tokens are passed through process environment, not command-line arguments. |

Certificate/key discovery also runs for folder/ZIP/repository and container scans. Serialized keys do not contain reliable creation/rotation dates; these are explicitly marked unavailable. Cloud versions supply lifecycle state, dates where available, rotation metadata, and exportability where supported. Expired/weak certificates and key-policy findings appear in the code/evidence viewer.

## Business context and recommendations

Context fields: `application`, `data_sensitivity` (public/internal/confidential/restricted), `data_types`, `business_criticality`, `data_lifetime_years`, `migration_years`, `quantum_horizon_years`, and `rotation_max_days`.

`asset_contexts` provides ordered `{ "path_pattern": "*/payments/*", "context": {...} }` overrides. Inputs are validated; omitted context is labeled `default-assumptions`. Risk combines classical issues, quantum vulnerability, Mosca's inequality, sensitivity, and criticality. HNDL exposure is highlighted for confidential/restricted data. The numeric model is a transparent prioritization heuristic, not a prediction of quantum arrival.

`usage` chooses signature/key-establishment/encryption/hash or auto inference. `latency_weight` and `cost_weight` rank compatible candidates. Default values are **relative planning estimates**, not measured milliseconds or currency. Supply `benchmarks: [{"algorithm":"ML-DSA-65","latency_ms":1.2,"cost_per_million":2.5}, ...]` for all candidates in the selected family to use measured ranking. `max_latency_ms` and `max_cost_per_million` are checked only against supplied measurements; missing measurements do not satisfy a budget. Candidate names and rankings are returned in `ecdat:recommendation`.

## CBOM contract

Every successful scan response is generated using `cyclonedx-python-lib` and validated with its strict CycloneDX 1.6 JSON validator. Business metadata uses namespaced properties: `ecdat:risk`, `ecdat:mosca`, `ecdat:recommendation`, `ecdat:discovery`, `ecdat:summary`, `ecdat:scan_context`, `ecdat:coverage`, `ecdat:discovery_errors`. Consumers parse these property values as JSON. The frontend decodes them for display, then strips convenience fields before export. Source snippets are omitted from saved history.

## CI/CD and authenticated internal systems

Set `ECDAT_API_KEY` on the backend to require bearer authentication (health probes remain public). Enter that token in Enterprise discovery for browser use. Provider credentials stay on the backend. Run the backend/CLI on a runner with network access to internal systems; SSH clones honor known_hosts and the runner's SSH agent.

```sh
python cli.py --config discovery.example.json --output cbom.json --fail-on high
```

Exit codes: 0 complete/pass, 1 findings exceed the gate, 2 request failure or incomplete discovery. Archive `cbom.json` as a CI artifact. Multiple applications can be scanned in one request with independent contexts; denied targets produce explicit partial coverage errors.

## Verification

```sh
python -m pytest tests -q
```

Tests generate certificates and multiple key types, perform live handshakes against a local TLS server, validate output schemas, exercise API auth/uploads/context validation and batch partial failures, and test provider/HSM adapters with mocked SDK responses. Real cloud accounts, private repositories, and physical HSMs require environment-specific integration tests with the credentials above.
