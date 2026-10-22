import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .scrubber import CATEGORIES, DEFAULT_ALLOWLIST, scrub

MAX_CHARS = int(os.environ.get("SCRUBBER_MAX_CHARS", "2000000"))
CONFIG_DIR = Path(os.environ.get("SCRUBBER_CONFIG_DIR", "/config"))
STATIC = Path(__file__).parent / "static"

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _read_lines(name: str) -> list[str]:
    p = CONFIG_DIR / name
    if not p.is_file():
        return []
    lines = p.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def _clean(items: list[str]) -> list[str]:
    out, seen = [], set()
    for item in items:
        s = item.strip()
        if not s or s.startswith("#") or len(s) > 500 or any(ord(c) < 32 for c in s):
            continue
        if s.lower() not in seen:
            seen.add(s.lower())
            out.append(s)
    return out


def _write_lines(name: str, items: list[str]) -> None:
    p = CONFIG_DIR / name
    header = []
    if p.is_file():
        for ln in p.read_text(encoding="utf-8").splitlines():
            if ln.strip() and not ln.strip().startswith("#"):
                break
            if ln.strip():
                header.append(ln)
    tmp = p.with_name(f".{name}.tmp")
    tmp.write_text("\n".join(header + items) + "\n", encoding="utf-8")
    os.replace(tmp, p)


class SettingsRequest(BaseModel):
    custom_keys: list[str] = Field(default_factory=list, max_length=5000)
    custom_terms: list[str] = Field(default_factory=list, max_length=5000)
    allowlist: list[str] = Field(default_factory=list, max_length=5000)


class ScrubRequest(BaseModel):
    text: str = Field(max_length=MAX_CHARS)
    categories: list[str] | None = None
    allowlist: list[str] | None = None
    custom_terms: list[str] | None = None
    custom_keys: list[str] | None = None


@app.get("/api/defaults")
def defaults():
    return {
        "categories": [{"id": k, "label": v} for k, v in CATEGORIES.items()],
        "allowlist": DEFAULT_ALLOWLIST + _read_lines("allowlist.txt"),
        "custom_terms": _read_lines("custom_terms.txt"),
        "custom_keys": _read_lines("sensitive_keys.txt"),
        "max_chars": MAX_CHARS,
    }


@app.put("/api/settings")
def save_settings(req: SettingsRequest):
    builtin = {d.lower() for d in DEFAULT_ALLOWLIST}
    try:
        _write_lines("sensitive_keys.txt", _clean(req.custom_keys))
        _write_lines("custom_terms.txt", _clean(req.custom_terms))
        _write_lines("allowlist.txt", [a for a in _clean(req.allowlist) if a.lower() not in builtin])
    except OSError as e:
        raise HTTPException(500, f"Cannot write to the config folder: {e.strerror}")
    return defaults()


@app.post("/api/scrub")
def api_scrub(req: ScrubRequest):
    cats = None if req.categories is None else [c for c in req.categories if c in CATEGORIES]
    r = scrub(req.text, cats, req.allowlist, req.custom_terms, req.custom_keys)
    return {"text": r.text, "findings": r.findings, "counts": r.counts}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
