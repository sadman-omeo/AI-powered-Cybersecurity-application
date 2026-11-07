
import json
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from backend.analyzer import run_analysis


BASE = Path(__file__).resolve().parent.parent
FRONTEND = BASE / "frontend"
UPLOADS = BASE / "data" / "uploads"
RESULTS = BASE / "data" / "results"

UPLOADS.mkdir(parents=True, exist_ok=True)
RESULTS.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD = 10 * 1024 * 1024

app = FastAPI(title="Cultive8 Security Log Analyzer")

lock = threading.Lock()

state = {
    "status": "idle",
    "filename": None,
    "processed": 0,
    "total": 0,
    "chunks": 0,
    "errors": 0,
    "message": "",
    "report": None
}


# Restore the last completed report when available
previous_report = RESULTS / "report.json"

if previous_report.exists():
    try:
        old = json.loads(
            previous_report.read_text(encoding="utf-8")
        )
        state.update({
            "status": old.get("status", "partial"),
            "filename": old.get("log_file"),
            "processed": old.get("total_entries", 0),
            "total": old.get("total_entries", 0),
            "chunks": old.get("chunks_processed", 0),
            "errors": len(old.get("errors", [])),
            "report": old
        })
    except (OSError, ValueError):
        pass


@app.get("/")
def homepage():
    return FileResponse(
        FRONTEND / "index.html",
        media_type="text/html"
    )


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "Cultive8 Analyzer"}


@app.get("/api/status")
def get_status():
    with lock:
        return {
            key: value
            for key, value in state.items()
            if key != "report"
        }


@app.get("/api/report")
def get_report():
    with lock:
        report = state["report"]

    if report is None:
        raise HTTPException(404, "No completed report available")

    return JSONResponse(report)


@app.get("/api/report/download")
def download_report():
    with lock:
        available = state["report"] is not None

    path = RESULTS / "report.json"

    if not available or not path.is_file():
        raise HTTPException(404, "Report is not available")

    return FileResponse(
        path,
        media_type="application/json",
        filename="security_report.json"
    )


def analysis_worker(file_path):

    def update_progress(progress):
        with lock:
            state.update(progress)

    try:
        report = run_analysis(
            log_path=file_path,
            output_dir=str(RESULTS),
            on_progress=update_progress
        )

        with lock:
            state["report"] = report
            state["status"] = report["status"]
            state["processed"] = report["total_entries"]
            state["total"] = report["total_entries"]
            state["chunks"] = report["chunks_processed"]
            state["errors"] = len(report["errors"])
            state["message"] = (
                "Analysis finished successfully."
                if report["status"] == "complete"
                else "Analysis finished with model errors."
            )

    except Exception as exc:
        with lock:
            state["status"] = "failed"
            state["message"] = str(exc)


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):

    filename = file.filename or ""
    extension = Path(filename).suffix.lower()

    if extension not in {".log", ".txt"}:
        raise HTTPException(
            400, "Only .log and .txt files are supported"
        )

    with lock:
        if state["status"] in {"running", "uploading"}:
            raise HTTPException(
                409, "Another analysis is already running"
            )

        state.update({
            "status": "uploading",
            "filename": filename,
            "processed": 0,
            "total": 0,
            "chunks": 0,
            "errors": 0,
            "message": "Uploading log file...",
            "report": None
        })

    path = UPLOADS / f"{uuid.uuid4().hex}{extension}"

    try:
        size = 0

        with path.open("wb") as destination:
            while True:
                data = await file.read(65536)

                if not data:
                    break

                size += len(data)

                if size > MAX_UPLOAD:
                    raise HTTPException(
                        413, "Maximum upload size is 10 MB"
                    )

                destination.write(data)

        if size == 0:
            raise HTTPException(400, "Uploaded file is empty")

    except Exception:
        path.unlink(missing_ok=True)

        with lock:
            state["status"] = "idle"
            state["message"] = "Upload failed"

        raise

    finally:
        await file.close()

    with lock:
        state["status"] = "running"
        state["message"] = "Analyzing server logs..."

    thread = threading.Thread(
        target=analysis_worker,
        args=(str(path),),
        daemon=True
    )

    thread.start()

    return {
        "started": True,
        "filename": filename,
        "message": "Analysis started"
    }
