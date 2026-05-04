from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import datetime, sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from predictor import predict, load_model

app = FastAPI(title="PhishGuard AI API", version="2.0.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

model, scaler, feature_names = load_model()
scan_history = []

class ScanRequest(BaseModel):
    url : Optional[str] = ""
    text: Optional[str] = ""

@app.get("/")
def root():
    return {"name":"PhishGuard AI API","version":"2.0.0","model_active":model is not None,"docs":"/docs","github":"https://github.com/mohammadshijan/PhishGuard-AI"}

@app.get("/health")
def health():
    return {"status":"healthy","model_loaded":model is not None,"timestamp":datetime.datetime.now().isoformat()}

@app.post("/scan")
def scan(request: ScanRequest):
    if not request.url and not request.text:
        raise HTTPException(status_code=400, detail="url or text required")
    result = predict(url=request.url or "", text=request.text or "", model=model, scaler=scaler, feature_names=feature_names)
    timestamp = datetime.datetime.now().isoformat()
    scan_history.insert(0, {"url":(request.url or request.text[:50])[:50],"risk_level":result["risk_level"],"risk_score":round(result["risk_score"]*100,1),"timestamp":timestamp})
    if len(scan_history) > 10: scan_history.pop()
    return {"risk_score":round(result["risk_score"],4),"risk_level":result["risk_level"],"risk_emoji":result["risk_emoji"],"risk_color":result["risk_color"],"top_signals":result["top_signals"],"scanned_url":request.url or "(text only)","timestamp":timestamp,"mode":"ML Model" if model else "Heuristic"}

@app.post("/scan/url")
def scan_url(url: str):
    if not url: raise HTTPException(status_code=400, detail="URL required")
    result = predict(url=url, model=model, scaler=scaler, feature_names=feature_names)
    return {"url":url,"risk_score":round(result["risk_score"]*100,1),"risk_level":result["risk_level"],"risk_emoji":result["risk_emoji"],"top_signals":result["top_signals"][:3],"safe":result["risk_level"]=="SAFE"}

@app.get("/history")
def history():
    return {"total_scans":len(scan_history),"history":scan_history}
