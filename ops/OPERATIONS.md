# Operating Selat Watch

## Passive providers

Provider endpoints are coded in `watch/adapters.py`. The program never requests the observed domain itself. Keys stay in environment variables. Supply them through a secret manager or a private shell session; never commit them or paste them into observation JSON.

- VirusTotal: `VT_API_KEY`; GET `/api/v3/domains/{domain}` with `x-apikey`.
- URLhaus: `URLHAUS_AUTH_KEY`; POST `/v1/host/` with `Auth-Key` and a form-encoded host. This is a reputation lookup, not a submission. URLhaus primarily describes malware distribution; no-results does not establish safety.

After importing an authorized non-synthetic observation, run:

```sh
.venv/bin/python app.py enrich your-recorded-domain.example --provider virustotal
.venv/bin/python app.py enrich your-recorded-domain.example --provider urlhaus
```

Replace the placeholder with a case already in your database. Synthetic-labelled records are rejected before any provider request. A provider response becomes a new observation; original evidence and analyst decisions remain. HTTP failures, timeouts, invalid response shapes and missing credentials are visible in Source health. Requests have a 20-second timeout and 5 MB response bound; redirects are rejected. Respect the provider's current quota/terms. No automatic retries conceal a 429.

## Certificate feed

Install the pinned websocket dependency, obtain an available authorized CertStream service endpoint and run a bounded session:

```sh
.venv/bin/python app.py watch-ct --url wss://YOUR-CT-SERVICE --seconds 300
```

The example endpoint is a placeholder. Historical Calidog service documentation establishes the message schema, not current service availability. Sessions accept 1–3600 seconds, close on completion, and log errors. Repeated canonical certificate observations deduplicate. The adapter is not a durable log follower: there is no cryptographic CT proof verification, cursor recovery, reconnect replay or loss guarantee. For auditable collection, archive your service's raw events and import them; use the service's own retention and continuity controls.

To run a reviewed bounded session on Linux, adapt `selat-ct.service.example` and `.timer.example`. They are templates, not installed services. A nonzero CLI exit is failure; investigate Source health before continuing. Keep provider retrieval separate from analyst UI startup.

## Digests and backups

Use your scheduler to execute `app.py digest` once daily and redirect stdout to a dated local Markdown file. Its default day is Asia/Kuala_Lumpur; it sends no email. The systemd timer example schedules a CT task, not an email job. Review duplicates, errors, case counts and labelled outcomes daily.

Stop the application before copying a database, or use SQLite's backup API while it is running:

```sh
.venv/bin/python -c "import sqlite3; src=sqlite3.connect('work/watch.db'); dst=sqlite3.connect('work/watch-backup.db'); src.backup(dst); dst.close(); src.close()"
```

Keep both originals and downloaded packs in access-controlled storage. Local SQLite files and screenshots are not encrypted. Define retention before importing sensitive operational observations. Restore by selecting a copied backup with `--db`; never overwrite an open database.

## Linux or existing EC2 host

No infrastructure was provisioned. On an already authorized Linux host, copy the product folder, install Python 3.11+, create the venv, install the pinned dependencies and run the same CLI. Use a dedicated OS user and owner-only database permissions. Bind the UI to loopback, then access it with an SSH tunnel:

```sh
ssh -L 8765:127.0.0.1:8765 your-existing-host
# On that host, from this product's directory:
.venv/bin/python app.py serve --port 8765
```

No inbound web port is necessary. Choose another free port if occupied. Public multi-user hosting requires authentication, authorization, TLS, operational logging, retention review, rate controls and a production server architecture; those are not implemented here. The read-only `snapshot` export is the sharing path delivered locally. No Lambda handler, Docker image or cloud deployment is claimed.

## Recovery

- Port occupied: use `--port 0` or select another free port. Never stop unrelated processes.
- Invalid import: correct only the reported rows and reimport; valid canonical observations deduplicate.
- Provider failure: preserve the prior observation, check environment configuration/terms/quota, then rerun explicitly.
- Stale dossier: allowlist changes and rescore refresh both queue and selected detail. Exports use the persisted assessment.
- False positive: record a benign verdict and reason. Use an exact-domain exception only after review; this preserves the original observation and audit events.
