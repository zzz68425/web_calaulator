# Certificate Transparency Monitor Tests

These standalone scripts cover every service currently listed at
`https://certificate.transparency.dev/monitors/`. They do not import or modify
the main application.

Run all providers against the default test target:

```powershell
uv run python tests/manual/ct_monitors/run_all.py
```

Run one provider:

```powershell
uv run python tests/manual/ct_monitors/hurricane_electric_test.py evs.ncku.edu.tw
```

Include child domains:

```powershell
uv run python tests/manual/ct_monitors/run_all.py ncku.edu.tw --include-subdomains
```

Every provider writes an individual log under `logs/ct_monitors/`. The all-in-one
runner also writes a summary log in that directory.

Save raw authenticated MerkleMap and Censys responses without putting tokens on
the command line or in a log:

```powershell
uv run python tests/manual/ct_monitors/authenticated_raw_search.py ncku.edu.tw --limit 50
```

The script reads tokens with a hidden prompt unless they already exist in the
process environment. Raw JSON is written under `logs/ct_monitors/raw/`.

## Credentials

| Provider | Environment variables | Scope |
| --- | --- | --- |
| Censys | `CENSYS_API_TOKEN`, `CENSYS_ORGANIZATION_ID` | Global search; paid search-capable plan required |
| MerkleMap | `MERKLEMAP_API_TOKEN` | Global search |
| Hardenize | `HARDENIZE_ORG`, `HARDENIZE_API_USERNAME`, `HARDENIZE_API_PASSWORD` | Account inventory only |
| Oh Dear | `OHDEAR_TOKEN`, `OHDEAR_MONITOR_ID` | Existing monitor only |
| Red Sift | `REDSIFT_API_KEY` | Account inventory only |
| Report URI | `REPORT_URI_API_KEY` | Configured account domains/current reports only |
| SSLMate Cert Spotter | `CERTSPOTTER_API_KEY` (optional) | Public evaluation works without a key |

Cloudflare, DigiCert, Keytos EZMonitor, and Stellastra do not expose an
equivalent arbitrary-domain certificate search API. Their scripts record that
capability result instead of pretending an account-monitoring API is a global
search API.
