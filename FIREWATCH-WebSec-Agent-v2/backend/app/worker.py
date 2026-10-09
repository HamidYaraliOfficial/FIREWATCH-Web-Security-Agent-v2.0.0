from __future__ import annotations
import asyncio,logging,time
from sqlalchemy import select
from .db import SessionLocal,init_db
from .models import Scan,ScanStatus
from .orchestrator import ScanOrchestrator
logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(name)s: %(message)s')
log=logging.getLogger('firewatch.worker')
def claim_one():
    db=SessionLocal()
    try:
        scan=db.scalar(select(Scan).where(Scan.status==ScanStatus.QUEUED).order_by(Scan.created_at.asc()).limit(1))
        if not scan:return None
        scan.status=ScanStatus.RUNNING; db.commit(); return scan.id
    finally: db.close()
async def process(scan_id):
    db=SessionLocal()
    try:
        scan=db.get(Scan,scan_id)
        if scan: await ScanOrchestrator(db).run(scan)
    finally: db.close()
def main():
    init_db();log.info('FIREWATCH worker started')
    while True:
        scan_id=claim_one()
        if scan_id:
            try: asyncio.run(process(scan_id))
            except Exception: log.exception('scan failed: %s',scan_id)
        else: time.sleep(1)
if __name__=='__main__': main()
