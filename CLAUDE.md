# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Portal DIM is a full-stack web application for network infrastructure management built on top of NetDB (`ndcli` CLI). It provides a UI for querying/managing IP pools, subnets, DNS records, and VLANs across multiple network domains.

**Tech Stack**: React 18 + Vite (frontend), FastAPI + Uvicorn (backend), Python 3.9+

## Commands

### Frontend (from `frontend/`)
```bash
npm install          # Install dependencies
npm run dev          # Start Vite dev server on :5173 (proxies /api to :4500)
npm run build        # Production build (minimum regression check before PR)
```

### Backend (from `backend/`)
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
./run.sh             # Start FastAPI on :4501
./stop.sh            # Stop backend
```

## Architecture

```
React Frontend (:5173) → FastAPI Backend (:4500) → ndcli subprocess → NetDB
```

### Frontend (`frontend/src/`)
- **App.jsx** (3300+ lines): Monolithic component handling 4 tabs:
  - Consultas ACS: Search pools/subnets/VLANs/DNS/IPs in ACS domains
  - Consultas IONOS: Search subnets/IPs in non-ACS domains
  - Gestión DNS: Create/delete DNS records
  - Importación IPs: CSV-based batch IP import workflow
- **api.js**: Fetch-based API client with session cookie handling
- **components/ResultsTable.jsx**: Reusable results display

### Backend (`backend/`)
- **main.py** (2656 lines): All endpoints + domain handlers. Key functions:
  - `_perform_search()`: Routes search type to handler (subnet/pool/vlan/ip/device/dns)
  - `search_across_domains()`: Tries query against layer3domains in priority order
  - `require_session()`: FastAPI dependency for protected endpoints
- **models.py**: Pydantic schemas (SearchQuery, ResultItem, ImportIPPayload)
- **settings.py**: Layer3domain list (11 domains), LDAP config
- **ndcli_exec.py**: Subprocess wrapper using contextvars for credentials
- **parsers.py**: Regex-based key:value block parser for ndcli output

### Session Management
- Cookie-based (15-min TTL), in-memory store (2048 limit)
- Fernet encryption for stored passwords
- LDAP authentication against `ldaps://ldap.1and1.org:636`

### Layer3Domain Strategy
Domains defined in `settings.py`. ACS queries use domains containing "acs", IONOS excludes them. Fallback search tries domains in priority order until success.

## Environment Variables

Create `.env` in root (falls back to `backend/.env`):
```
LDAP_BIND_PASSWORD=<ldap_service_password>
SESSION_SECRET=<32+_char_secret>
FERNET_KEY=<optional, auto-generated>
```

## Key Patterns

**Python**: PEP 8, 4-space indent, snake_case, type hints. Shell commands built via helpers (`_format_ndcli_command`).

**JavaScript**: 2-space indent, camelCase variables, PascalCase components. Heavy useState/useMemo usage. Theme via style objects.

**Import logs**: Written to `backend/logs/import-YYYY-MM-DD.log`

## API Endpoints (key ones)

- `POST /api/auth/login|logout`, `GET /api/auth/session`
- `GET /api/search` - Main search (type: subnet/pool/vlan/ip/device/dns)
- `POST /api/ip/reserve|release|edit`
- `POST /api/dns/check|create|delete`
- `POST /api/import/ip-info|dryrun|execute`

## Adding Features

**New search type**: Add handler in `main.py`, case in `_perform_search()`, UI option in `App.jsx` SEARCH_TYPES arrays.

**New endpoint**: Define Pydantic models in `models.py`, handler in `main.py` with `@app.post()`, client function in `api.js`.
