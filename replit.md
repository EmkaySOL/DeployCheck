# DeployCheck

DeployCheck statically inspects project ZIP archives for likely secrets, missing environment declarations, and a small set of deployment configuration risks.

## Run & Operate

- The managed `artifacts/api-server: API Server` workflow serves the FastAPI routes under `/api`.
- The managed `artifacts/deploycheck: web` workflow serves the React interface.
- `uv run --project . pytest -q` — run scanner and API tests.
- `pnpm run typecheck` — typecheck the shared TypeScript workspace.
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API client and schemas after OpenAPI changes.
- No database, account system, or external API is required.

## Stack

- Frontend: React, Vite, TypeScript, and generated React Query API hooks.
- API: Python, FastAPI, and Pydantic.
- Python dependencies: `pyproject.toml` and `uv.lock`.
- API contract: `lib/api-spec/openapi.yaml`, generated with Orval.
- Tests: pytest and FastAPI TestClient.

## Where things live

- `artifacts/deploycheck` — user-facing upload and findings interface.
- `artifacts/api-server/deploycheck_api` — FastAPI app, response schemas, and ZIP scanner.
- `artifacts/api-server/tests` — API and scanner tests.
- `lib/api-spec/openapi.yaml` — source of truth for the API contract.
- `samples/safe_project` and `samples/unsafe_project` — synthetic demo projects.

## Architecture decisions

- Scans are in-memory and stateless; uploaded archives and scan results are not persisted.
- ZIP entries are inspected without extracting files or executing project code.
- Findings treat matches as potential risks and redact credential-like values before returning evidence.
- No readiness score is shown; this MVP does not certify that a project is secure.

## Product

- Upload a project ZIP, run a static scan, review severity-ranked findings, and export a Markdown report.
- Checks include credential patterns, environment-variable declarations, private environment files in the archive, `.gitignore` presence, and enabled debug settings.
- Scans apply compressed-size, entry-count, file-count, per-file, total-uncompressed-size, compression-ratio, and runtime limits.

## User preferences

_No standing preferences recorded._

## Gotchas

- After changing `lib/api-spec/openapi.yaml`, rerun codegen before typechecking or using generated hooks.
- Example credentials in tests and samples are synthetic only.

## Pointers

- See `.local/skills/pnpm-workspace/SKILL.md` for workspace structure and artifact routing.
