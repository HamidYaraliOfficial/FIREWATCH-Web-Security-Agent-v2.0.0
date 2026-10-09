from __future__ import annotations
import asyncio, logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .config import settings
from .db import get_db, init_db, SessionLocal
from .models import Asset, Finding, Page, Scan, ScanEvent, ScanStatus
from .schemas import AssetOut, EventOut, FindingOut, ScanCreate, ScanDetail, ScanSummary
from .scope import ScopePolicy, ScopeViolation
from .orchestrator import ScanOrchestrator
logging.basicConfig(level=getattr(logging,settings.log_level.upper(),logging.INFO))
logger=logging.getLogger('firewatch.api')
HERE=Path(__file__).resolve()
ROOT=(HERE.parents[2] if (HERE.parents[2]/'frontend').exists() else HERE.parents[1])
FRONTEND=ROOT/'frontend'
async def queue_loop(stop_event:asyncio.Event):
    while not stop_event.is_set():
        db=SessionLocal()
        try:
            scan=db.scalar(select(Scan).where(Scan.status==ScanStatus.QUEUED).order_by(Scan.created_at.asc()).limit(1))
            if scan:
                scan.status=ScanStatus.RUNNING; db.commit()
                try:
                    await ScanOrchestrator(db).run(scan)
                except Exception: logger.exception('queued scan failed: %s',scan.id)
            else:
                await asyncio.sleep(0.75)
        finally: db.close()
@asynccontextmanager
async def lifespan(_app):
    init_db(); stop=asyncio.Event(); task=asyncio.create_task(queue_loop(stop))
    try: yield
    finally: stop.set(); task.cancel();
app=FastAPI(title=settings.app_name,version='2.0.0',docs_url='/docs',redoc_url='/redoc',lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in settings.cors_origins.split(',') if x.strip()],allow_credentials=False,allow_methods=['GET','POST','OPTIONS','DELETE'],allow_headers=['Content-Type','Authorization'])
@app.get('/health')
def health(): return {'status':'ok','service':'firewatch-api','version':'2.0.0','scanner':'authorized-scope-controlled'}
@app.post('/api/v1/scans',response_model=ScanSummary,status_code=201)
def create_scan(payload:ScanCreate,db:Session=Depends(get_db)):
    if settings.require_scope_ack and not payload.scope_acknowledged: raise HTTPException(400,'scope_acknowledged must be true for an active security assessment')
    target=str(payload.target_url)
    try: ScopePolicy.from_root(target,exclusions=payload.exclusions,allow_private_targets=settings.allow_private_targets,allowed_hosts=payload.allowed_hosts)
    except ScopeViolation as exc: raise HTTPException(400,str(exc))
    cfg=payload.model_dump(exclude={'target_url','project_id','scope_acknowledged'})
    scan=Scan(project_id=payload.project_id,target_url=target,config=cfg)
    db.add(scan); db.commit(); db.refresh(scan); return scan
@app.get('/api/v1/scans',response_model=list[ScanSummary])
def list_scans(limit:int=50,db:Session=Depends(get_db)):
    return list(db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(min(max(limit,1),200))))
@app.get('/api/v1/scans/{scan_id}',response_model=ScanDetail)
def get_scan(scan_id:str,db:Session=Depends(get_db)):
    scan=db.get(Scan,scan_id)
    if not scan: raise HTTPException(404,'Scan not found')
    counts={
        'pages_count':db.scalar(select(func.count()).select_from(Page).where(Page.scan_id==scan.id)) or 0,
        'assets_count':db.scalar(select(func.count()).select_from(Asset).where(Asset.scan_id==scan.id)) or 0,
        'findings_count':db.scalar(select(func.count()).select_from(Finding).where(Finding.scan_id==scan.id)) or 0,
        'events_count':db.scalar(select(func.count()).select_from(ScanEvent).where(ScanEvent.scan_id==scan.id)) or 0,
    }
    config=dict(scan.config or {})
    if config.get('auth_cookies'): config['auth_cookies']='[REDACTED]'
    if config.get('request_headers'):
        config['request_headers']={k:('[REDACTED]' if k.lower() in {'authorization','cookie','x-api-key'} else v) for k,v in config['request_headers'].items()}
    if config.get('authorization_profiles'):
        config['authorization_profiles']=[{'name':x.get('name','profile'),'headers':{k:'[REDACTED]' for k in (x.get('headers') or {})}} for x in config['authorization_profiles']]
    data={c.name:getattr(scan,c.name) for c in Scan.__table__.columns}; data['config']=config; data.update(counts); return ScanDetail.model_validate(data)
@app.get('/api/v1/scans/{scan_id}/findings',response_model=list[FindingOut])
def list_findings(scan_id:str,db:Session=Depends(get_db)):
    if not db.get(Scan,scan_id): raise HTTPException(404,'Scan not found')
    return list(db.scalars(select(Finding).where(Finding.scan_id==scan_id).order_by(Finding.risk_score.desc())))
@app.get('/api/v1/scans/{scan_id}/events',response_model=list[EventOut])
def list_events(scan_id:str,db:Session=Depends(get_db)):
    if not db.get(Scan,scan_id): raise HTTPException(404,'Scan not found')
    return list(db.scalars(select(ScanEvent).where(ScanEvent.scan_id==scan_id).order_by(ScanEvent.created_at.asc())))
@app.get('/api/v1/scans/{scan_id}/assets',response_model=list[AssetOut])
def list_assets(scan_id:str,limit:int=500,db:Session=Depends(get_db)):
    if not db.get(Scan,scan_id): raise HTTPException(404,'Scan not found')
    return list(db.scalars(select(Asset).where(Asset.scan_id==scan_id).order_by(Asset.id).limit(min(max(limit,1),2000))))
@app.post('/api/v1/scans/{scan_id}/cancel')
def cancel_scan(scan_id:str,db:Session=Depends(get_db)):
    scan=db.get(Scan,scan_id)
    if not scan: raise HTTPException(404,'Scan not found')
    if scan.status in {ScanStatus.QUEUED,ScanStatus.RUNNING}: scan.status=ScanStatus.CANCELED; db.commit()
    return {'id':scan.id,'status':scan.status.value}
@app.get('/api/v1/scans/{scan_id}/report')
def report(scan_id:str,format:str='html',db:Session=Depends(get_db)):
    scan=db.get(Scan,scan_id)
    if not scan: raise HTTPException(404,'Scan not found')
    report=next((r for r in scan.reports if r.format==format),None)
    if not report or not Path(report.path).exists(): raise HTTPException(404,'Report not available yet')
    media='text/html' if format=='html' else 'application/json'
    return FileResponse(report.path,media_type=media,filename=Path(report.path).name)
@app.get('/',response_class=HTMLResponse)
def ui():
    path=FRONTEND/'index.html'
    if path.exists(): return path.read_text(encoding='utf-8')
    return '<h1>FIREWATCH Web Security Agent</h1><p>API: <a href="/docs">/docs</a></p>'
@app.get('/static/{file_path:path}')
def static(file_path:str):
    path=FRONTEND/'static'/file_path
    if not path.exists(): raise HTTPException(404,'Not found')
    return FileResponse(path)
