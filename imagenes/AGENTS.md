# Repository Guidelines

## Project Structure & Module Organization
- `backend/`: FastAPI service. `main.py` hosts all endpoints, `models.py` defines Pydantic schemas, and `ndcli_exec.py` wraps `ndcli`. Daily import logs are written under `logs/import-YYYY-MM-DD.log`.
- `frontend/`: Vite + React client. `src/App.jsx` drives both the DIM search tools and the IP import workflow; shared UI pieces sit in `src/components/`.
- `logs/`: Created on demand for operational logs (no logs are committed by default).
- Root scripts (`run.sh`, `stop.sh`) orchestrate local start/stop for both tiers.

## Build, Test, and Development Commands
- `cd frontend && npm install`: install UI dependencies.
- `cd frontend && npm run dev`: start the Vite dev server on localhost with hot reload.
- `cd frontend && npm run build`: produce the production bundle; treat this as the minimum regression check before a PR.
- `cd backend && python -m venv .venv && source .venv/bin/activate`: set up an isolated Python environment.
- `cd backend && pip install -r requirements.txt`: install API dependencies.
- `cd backend && ./run.sh`: launch the FastAPI server with auto-reload (port 4500).

## Coding Style & Naming Conventions
- Python: follow PEP 8 (4-space indentation, snake_case names, type hints preferred). Keep application logs in `logs/` via `_write_import_log`.
- JavaScript/JSX: use the existing 2-space indentation, camelCase for variables/functions, and PascalCase for components. Keep React hooks at the top of the component and memoize expensive calculations.
- Strings that feed shell commands must be built with care—prefer helper utilities (e.g., `_format_ndcli_command`) over manual concatenation.

## Testing Guidelines
- No automated test suite exists yet. Until tests are introduced, run `npm run build` and exercise critical flows manually (CSV import, dry run, confirm).
- When adding backend logic, consider lightweight unit tests with `pytest`; store them under `backend/tests/` if introduced.

## Commit & Pull Request Guidelines
- Use concise, imperative commit messages (e.g., `Add import log writer`). Group related backend/frontend changes together.
- Reference work items with `Refs #123` or similar when applicable, and note manual verification steps in the commit body.
- PRs should include: a clear summary, screenshots or CLI excerpts for UI/API changes, explicit test notes (`npm run build`, manual flows), and mention of any new configuration or logging artifacts.

