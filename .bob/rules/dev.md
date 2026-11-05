# HoneyMap Dev Rules

## Server management
- NEVER start uvicorn or any long-running server using `&` in a shell command — it causes the tool to hang.
- ALWAYS use `background: true` on the `execute_command` tool when starting servers, watchers, or any process that does not exit on its own.
- To restart the server: first run `fuser -k 8000/tcp 2>/dev/null; sleep 1; true` as a normal (non-background) command, then start uvicorn with `background: true`.
- Never chain a server start with `&&` after other commands — start it in its own dedicated background call.

## Project layout
- Backend: `backend/` — FastAPI, run with `uvicorn backend.main:app --port 8000`
- Frontend: `frontend/` — static HTML, served with `python -m http.server 5500` (background)
- DB: `backend/honeymap.db` — SQLite, auto-created on first run
- Env: `.env` in repo root — set `ABUSEIPDB_KEY=` here

## Git workflow
- Working branch: `person-a`
- Always merge to `master` after committing: `git checkout master && git merge person-a --no-edit && git push origin master && git checkout person-a`
