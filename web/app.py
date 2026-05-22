"""
web/app.py

FastAPI uygulaması — HTTP endpoint'leri ve WebSocket handler'ı.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from web import scan_manager

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="AI Destekli Web Zafiyet Tarayıcısı", version="1.0")

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


# ---------------------------------------------------------------------------
# Pydantic modelleri
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target: str
    modules: Optional[List[str]] = None
    no_llm: bool = False
    cookie: Optional[str] = None
    timeout: int = 5


# ---------------------------------------------------------------------------
# Sayfalar
# ---------------------------------------------------------------------------

@app.get("/")
async def index():
    return FileResponse(os.path.join(_STATIC_DIR, "index.html"))


@app.get("/report/{scan_id}")
async def report_page(scan_id: str):
    return FileResponse(os.path.join(_STATIC_DIR, "report.html"))


# ---------------------------------------------------------------------------
# API endpoint'leri
# ---------------------------------------------------------------------------

@app.post("/api/scan/start")
async def start_scan(req: ScanRequest):
    try:
        scan_id = await scan_manager.start_scan(
            target=req.target,
            modules=req.modules,
            no_llm=req.no_llm,
            cookie=req.cookie,
            timeout=req.timeout,
        )
    except RuntimeError as exc:
        if str(exc) == "too_many_scans":
            raise HTTPException(status_code=429, detail="Maksimum eş zamanlı tarama limitine ulaşıldı.")
        raise HTTPException(status_code=500, detail=str(exc))
    return {"scan_id": scan_id}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    job = scan_manager.get_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı.")
    return _job_summary(job)


@app.delete("/api/scan/{scan_id}")
async def cancel_scan(scan_id: str):
    ok = await scan_manager.cancel_scan(scan_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı veya zaten tamamlandı.")
    return {"cancelled": True}


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str):
    job = scan_manager.get_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı.")
    if job.status != "done":
        raise HTTPException(status_code=409, detail=f"Tarama henüz tamamlanmadı: {job.status}")
    if not job.report:
        raise HTTPException(status_code=404, detail="Rapor dosyası bulunamadı.")
    return JSONResponse(content=job.report)


@app.get("/api/scans")
async def list_scans():
    jobs = scan_manager.list_jobs(limit=20)
    return [_job_summary(j) for j in jobs]


@app.post("/api/targets/dvwa/setup")
async def dvwa_setup():
    """DVWA veritabanını kur, login ol, kullanılabilir cookie döndür."""
    base = "http://dvwa"
    try:
        sess = requests.Session()
        sess.get(f"{base}/setup.php", timeout=10)
        sess.post(
            f"{base}/setup.php",
            data={"create_db": "Create / Reset Database"},
            timeout=15,
        )
        r = sess.get(f"{base}/login.php", timeout=10, allow_redirects=False)
        token = ""
        for line in r.text.splitlines():
            if "user_token" in line and "value=" in line:
                token = line.split("value='")[1].split("'")[0]
                break
        sess.post(
            f"{base}/login.php",
            data={
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": token,
            },
            timeout=10,
            allow_redirects=False,
        )
        sess.cookies.set("security", "low", domain="dvwa", path="/")
        phpsessid = sess.cookies.get("PHPSESSID")
        if not phpsessid:
            raise HTTPException(status_code=502, detail="PHPSESSID alınamadı.")
        cookie = f"PHPSESSID={phpsessid}; security=low"
        return {"cookie": cookie, "url": "http://dvwa/"}
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"DVWA'ya erişilemiyor: {exc}")


@app.get("/api/targets")
async def list_targets():
    targets = [
        {
            "name": "DVWA",
            "url": "http://dvwa/",
            "description": "Damn Vulnerable Web Application — PHP/MySQL tabanlı klasik test ortamı",
            "note": "Cookie gerekli: PHPSESSID=...; security=low",
            "modules": ["A01", "A03", "A07", "A10"],
        },
        {
            "name": "Juice Shop",
            "url": "http://juice-shop:3000/",
            "description": "OWASP Juice Shop — modern Node.js/Angular tabanlı test ortamı",
            "note": "",
            "modules": ["A02", "A05", "A06", "A08"],
        },
        {
            "name": "WebGoat",
            "url": "http://webgoat:8080/WebGoat/",
            "description": "OWASP WebGoat — Java tabanlı, eğitim odaklı test ortamı",
            "note": "",
            "modules": ["A07", "A08", "A09"],
        },
    ]
    return targets


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

@app.websocket("/ws/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    scan_manager.register_ws(scan_id, websocket)

    job = scan_manager.get_job(scan_id)
    if job:
        for line in job.log_buffer:
            try:
                await websocket.send_json({"type": "log", "level": "INFO", "message": line})
            except Exception:
                break

        if job.status in ("done", "error", "cancelled") and job.report:
            try:
                await websocket.send_json({
                    "type": "scan_complete",
                    "exit_code": 0 if job.status == "done" else 1,
                    "duration": round((job.finished_at or 0) - job.started_at, 2),
                    "total_findings": job.report.get("summary", {}).get("total_findings", 0),
                    "report_id": scan_id,
                    "report": job.report,
                })
            except Exception:
                pass

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        scan_manager.unregister_ws(scan_id, websocket)


# ---------------------------------------------------------------------------
# Yardımcı
# ---------------------------------------------------------------------------

def _job_summary(job: scan_manager.ScanJob) -> Dict[str, Any]:
    return {
        "scan_id": job.scan_id,
        "status": job.status,
        "target": job.target,
        "modules": job.modules,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "total_findings": job.report["summary"]["total_findings"] if job.report else None,
    }
