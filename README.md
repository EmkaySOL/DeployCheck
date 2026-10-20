# DeployCheck

DeployCheck is a small pre-deployment checker for developers. Upload a ZIP of a project to look for likely hardcoded credentials, missing environment-variable declarations, and a few common configuration risks.

It performs static inspection only. Scanned code is never executed, scan results are not saved, and credential-like values are redacted from responses. Findings can be false positives or false negatives; this is not a security certification.

## Run in Replit

Open the DeployCheck preview. The API and web workflows run as managed services. The health endpoint is `/api/healthz`; interactive API docs are at `/api/docs`.

## Local setup

Requirements: Node.js with pnpm, Python 3.13+, and uv.

```bash
pnpm install
uv sync
uv run pytest -q
```

The API can be run locally from the workspace root:

```bash
uv run uvicorn deploycheck_api.main:app \
  --app-dir artifacts/api-server \
  --host 0.0.0.0 \
  --port 8080
```

The scanner endpoints are served under `/api`:

- `GET /api/healthz`
- `POST /api/v1/scans` — multipart form field `archive`, containing a ZIP file
- `GET /api/docs` — interactive API documentation

To run the web development server, use its managed Replit workflow. The frontend calls the API through the shared `/api` path.

## Tests and code generation

```bash
uv run pytest -q
pnpm --filter @workspace/api-spec run codegen
pnpm run typecheck
```

The OpenAPI source of truth is `lib/api-spec/openapi.yaml`. Regenerate hooks and schemas after changing it.

## Scan rules

- `SECRET001` — private-key header found (critical).
- `SECRET002` — token resembling a documented provider format (high).
- `SECRET003` — non-placeholder value assigned to a sensitive setting (high).
- `ENV001` — referenced environment variable missing from a supported sample file (medium).
- `ENV002` — blank variable declaration in a sample environment file (low).
- `CFG001` — no `.gitignore` found (low; absence alone does not mean files are tracked).
- `CFG002` — a non-example `.env` file is present in the archive (medium; the ZIP does not establish Git tracking).
- `CFG003` — a supported debug setting appears enabled (medium).

Supported environment samples are `.env.example`, `.env.sample`, and `.env.template`. Binary and unsupported files, common dependency/build/cache directories, and oversized files are skipped.

## Upload limits

The scanner caps compressed uploads at 12 MiB, archive entries at 1,000, regular files at 500, individual scanned files at 1 MiB, and total declared uncompressed archive size at 40 MiB. It also skips unusually compressed files and stops a scan that exceeds its time budget. Limits are deliberately conservative for this MVP.

## Demo samples

The `samples/safe_project` and `samples/unsafe_project` folders contain synthetic demo content. Zip either folder before uploading. Any credential-like strings in the unsafe sample are fake and must never be replaced with real credentials.

## Project layout

- `artifacts/deploycheck` — React web interface.
- `artifacts/api-server/deploycheck_api` — FastAPI API and scanner.
- `artifacts/api-server/tests` — API and scanner tests.
- `lib/api-spec/openapi.yaml` — API contract.
