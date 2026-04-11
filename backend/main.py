from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from backend.database import get_logs
from backend.blocker import blocked_domains, block_domain
import threading
from backend.sniffer import start_sniffer

app = FastAPI()

app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/")
def home():
    return FileResponse("frontend/index.html")

@app.get("/logs")
def logs():
    return get_logs()

@app.get("/blocked")
def get_blocked():
    return list(blocked_domains)

threading.Thread(target=start_sniffer, daemon=True).start()
