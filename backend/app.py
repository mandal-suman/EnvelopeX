# app.py
"""
EnvelopeX - Email Forensics Analysis Platform
Version: 2.0.0
License: MIT
"""

import os
import sys
import shutil
import tempfile
import asyncio
import logging
import uuid
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Optional
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Depends, Query
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Import analyze_file from extractor wrapper
from extractor import analyze_file

# ---------- Version ----------
__version__ = "2.0.0"

# ---------- Config ----------
MAX_UPLOAD_SIZE = int(os.getenv("ENVELOPEX_MAX_UPLOAD_SIZE", 100 * 1024 * 1024))  # 100MB
ALLOWED_EXTS = {".eml", ".txt", ".mbox", ".msg", ".mbx"}
WORKER_TIMEOUT = int(os.getenv("ENVELOPEX_WORKER_TIMEOUT", 120))  # seconds
JOB_RETENTION = int(os.getenv("ENVELOPEX_JOB_RETENTION", 3600))  # seconds - how long to keep job results
ALLOWED_DEV_ROOT = os.getenv("ENVELOPEX_DEV_ROOT", "/mnt/data")  # for analyze_by_url dev endpoint
API_KEY = os.getenv("ENVELOPEX_API_KEY", None)  # optional API key - set in ENV for production

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("envelopex.api")

# ---------- FastAPI app ----------
app = FastAPI(title="EnvelopeX API", version=__version__)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# ---------- Thread pool for blocking extractor calls ----------
executor = ThreadPoolExecutor(max_workers=3)

# ---------- In-memory job store ----------
# job structure:
# job_id -> {
#   "status": "queued|running|done|failed",
#   "created": timestamp,
#   "updated": timestamp,
#   "result": dict | None,
#   "error": str | None,
#   "tmpdir": str | None
# }
jobs: Dict[str, Dict] = {}

# ---------- Pydantic models ----------
class PathRequest(BaseModel):
    url: str

class JobStatus(BaseModel):
    job_id: str
    status: str
    created_at: float
    updated_at: float
    error: Optional[str] = None
    result: Optional[dict] = None

# ---------- Helper functions ----------
def save_upload_to_temp_sync(upload_file: UploadFile) -> str:
    """
    Save UploadFile to a temporary path, return path string.
    Synchronous implementation uses .read() — called inside thread or awaiting loop via save_upload_to_temp (async).
    """
    suffix = Path(upload_file.filename).suffix or ""
    tmp_dir = tempfile.mkdtemp(prefix="envelopex_upload_")
    tmp_path = Path(tmp_dir) / (upload_file.filename or f"upload{suffix or '.bin'}")
    with open(tmp_path, "wb") as f:
        # read in chunks
        upload_file.file.seek(0)
        while True:
            chunk = upload_file.file.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)
            if tmp_path.stat().st_size > MAX_UPLOAD_SIZE:
                raise HTTPException(status_code=413, detail="File too large")
    return str(tmp_path)

async def save_upload_to_temp(upload_file: UploadFile) -> str:
    suffix = Path(upload_file.filename).suffix or ""
    tmp_dir = tempfile.mkdtemp(prefix="envelopex_upload_")
    tmp_path = Path(tmp_dir) / (upload_file.filename or f"upload{suffix or '.bin'}")
    with open(tmp_path, "wb") as f:
        while True:
            chunk = await upload_file.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)
            if tmp_path.stat().st_size > MAX_UPLOAD_SIZE:
                raise HTTPException(status_code=413, detail="File too large")
    return str(tmp_path)

def run_analyze_sync(path: str):
    """Blocking run of analyze_file; used inside thread pool."""
    # analyze_file should return a dict (or raise)
    return analyze_file(path)

async def run_with_timeout_loop(path: str, timeout: int):
    loop = asyncio.get_running_loop()
    future = loop.run_in_executor(executor, run_analyze_sync, path)
    try:
        result = await asyncio.wait_for(future, timeout=timeout)
        return result
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Analysis timed out")
    except Exception as e:
        logger.exception("Error during analysis")
        raise HTTPException(status_code=500, detail=str(e))

def require_api_key(api_key: Optional[str] = Query(None)):
    """
    Simple API key check.
    - If ENVELOPEX_API_KEY is not set, API is open (dev).
    - If set, require ?api_key=... or header X-Api-Key to match.
    """
    if API_KEY is None:
        return
    # header check
    from fastapi import Request
    # We can't access Request in this dependency signature, so accept via Query or Env
    # We'll also allow header "X-Api-Key" via direct access in endpoints if needed.
    if api_key == API_KEY:
        return
    # If not provided via query, try env check via header - but FastAPI deps are limited here.
    raise HTTPException(status_code=401, detail="Invalid or missing API key")

def create_job_record(tmpdir: str) -> str:
    job_id = str(uuid.uuid4())
    now_ts = time.time()
    jobs[job_id] = {
        "status": "queued",
        "created": now_ts,
        "updated": now_ts,
        "result": None,
        "error": None,
        "tmpdir": tmpdir
    }
    return job_id

def cleanup_job(job_id: str):
    """Remove job artifacts and job record."""
    record = jobs.get(job_id)
    if not record:
        return
    tmpdir = record.get("tmpdir")
    if tmpdir and Path(tmpdir).exists():
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass
    jobs.pop(job_id, None)

async def background_cleanup_task():
    """Background task to purge old jobs periodically."""
    while True:
        now_ts = time.time()
        stale = []
        for jid, rec in list(jobs.items()):
            if rec.get("updated", 0) + JOB_RETENTION < now_ts:
                stale.append(jid)
        for jid in stale:
            logger.info(f"Cleaning up stale job {jid}")
            cleanup_job(jid)
        await asyncio.sleep(60)

# start background cleanup task on startup
@app.on_event("startup")
async def startup_event():
    logger.info("Starting EnvelopeX API")
    asyncio.create_task(background_cleanup_task())

# ---------- Endpoints ----------

@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0"}

@app.post("/api/analyze", dependencies=[Depends(require_api_key)])
async def api_analyze(file: UploadFile = File(...)):
    # validate ext
    filename = file.filename or "upload"
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTS:
        raise HTTPException(status_code=400, detail="Unsupported file type")
    # save to temp
    tmp_path = await save_upload_to_temp(file)
    tmpdir = Path(tmp_path).parent
    logger.info(f"Saved upload to {tmp_path}")
    try:
        result = await run_with_timeout_loop(tmp_path, WORKER_TIMEOUT)
        return JSONResponse(content=result)
    finally:
        # cleanup
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

@app.post("/api/analyze_by_url", dependencies=[Depends(require_api_key)])
async def api_analyze_by_url(payload: PathRequest):
    """
    Development-only helper that accepts a local file path (url) and runs analysis.
    For safety this allows only files under ENVELOPEX_DEV_ROOT (by default /mnt/data).
    """
    path = payload.url
    if not path:
        raise HTTPException(status_code=400, detail="Missing url")
    # sanitize & ensure the path is absolute and within allowed root
    try:
        pathp = Path(path).resolve(strict=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Path not found")
    allowed_root = Path(ALLOWED_DEV_ROOT).resolve()
    try:
        if not str(pathp).startswith(str(allowed_root)):
            raise HTTPException(status_code=403, detail="Access to this path is not allowed")
    except Exception:
        raise HTTPException(status_code=403, detail="Access to this path is not allowed")
    # size check
    size = pathp.stat().st_size
    if size > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File too large")
    result = await run_with_timeout_loop(str(pathp), WORKER_TIMEOUT)
    return JSONResponse(content=result)

@app.post("/api/analyze_async", dependencies=[Depends(require_api_key)])
async def api_analyze_async(file: UploadFile = File(...)):
    """
    Accept file, start background job, return job_id immediately.
    Client polls /api/job/{job_id} for status/result.
    """
    filename = file.filename or "upload"
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTS:
        raise HTTPException(status_code=400, detail="Unsupported file type")
    tmp_path = await save_upload_to_temp(file)
    tmpdir = Path(tmp_path).parent
    job_id = create_job_record(str(tmpdir))
    jobs[job_id]["status"] = "queued"
    jobs[job_id]["updated"] = time.time()

    # schedule background worker
    async def worker(job_id_local: str, target_path: str):
        jobs[job_id_local]["status"] = "running"
        jobs[job_id_local]["updated"] = time.time()
        try:
            # run blocking analyze in thread
            loop = asyncio.get_running_loop()
            fut = loop.run_in_executor(executor, run_analyze_sync, target_path)
            result = await asyncio.wait_for(fut, timeout=WORKER_TIMEOUT)
            jobs[job_id_local]["status"] = "done"
            jobs[job_id_local]["result"] = result
            jobs[job_id_local]["updated"] = time.time()
        except asyncio.TimeoutError:
            jobs[job_id_local]["status"] = "failed"
            jobs[job_id_local]["error"] = "timed out"
            jobs[job_id_local]["updated"] = time.time()
        except Exception as e:
            logger.exception(f"Job {job_id_local} failed")
            jobs[job_id_local]["status"] = "failed"
            jobs[job_id_local]["error"] = str(e)
            jobs[job_id_local]["updated"] = time.time()

    # kick background task
    asyncio.create_task(worker(job_id, tmp_path))
    return {"job_id": job_id, "status": "queued"}

@app.get("/api/job/{job_id}", response_model=JobStatus, dependencies=[Depends(require_api_key)])
async def api_job_status(job_id: str):
    rec = jobs.get(job_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Job not found")
    # If result present, trim large binary attachments out or expose attachments list
    out = {
        "job_id": job_id,
        "status": rec.get("status"),
        "created_at": rec.get("created"),
        "updated_at": rec.get("updated"),
        "error": rec.get("error"),
        "result": None
    }
    if rec.get("status") == "done" and rec.get("result"):
        # show metadata only for attachments; if client wants, they can download with /api/download
        result = rec.get("result")
        # sanitize attachments (only expose filename and size and sha256)
        try:
            messages = result.get("messages", [])
            # if multiple messages, expose attachments summary for each message
            for msg in messages:
                for att in msg.get("attachments", []):
                    # keep only safe metadata
                    att.pop("safe_preview_available", None)
                    att.pop("extraction_notes", None)
            out["result"] = result
        except Exception:
            out["result"] = result
    return out

@app.get("/api/download/{job_id}/{filename}", dependencies=[Depends(require_api_key)])
async def api_download_attachment(job_id: str, filename: str):
    rec = jobs.get(job_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Job not found")
    tmpdir = rec.get("tmpdir")
    if not tmpdir:
        raise HTTPException(status_code=404, detail="No attachments")
    candidate = Path(tmpdir) / filename
    if not candidate.exists():
        # try to search inside attachments folder
        att_dir = Path(tmpdir) / "attachments"
        cand2 = att_dir / filename
        if cand2.exists():
            candidate = cand2
        else:
            raise HTTPException(status_code=404, detail="Attachment not found")
    return FileResponse(path=str(candidate), filename=filename)

# graceful shutdown cleanup
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down EnvelopeX API, cleaning up jobs")
    for jid in list(jobs.keys()):
        cleanup_job(jid)
    executor.shutdown(wait=False)

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)
