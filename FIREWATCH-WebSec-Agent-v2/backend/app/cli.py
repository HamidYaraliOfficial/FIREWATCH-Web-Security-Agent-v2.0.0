from __future__ import annotations
import argparse,asyncio
from .db import SessionLocal,init_db
from .models import Scan,ScanStatus
from .orchestrator import ScanOrchestrator
from .scope import ScopePolicy
from .config import settings
async def run(args):
    init_db()
    ScopePolicy.from_root(args.url,allow_private_targets=settings.allow_private_targets)
    db=SessionLocal(); scan=Scan(target_url=args.url,config={'max_pages':args.pages,'max_depth':args.depth,'max_endpoints':args.endpoints,'request_delay_ms':args.delay,'enable_browser':not args.no_browser,'enable_api_introspection':not args.no_graphql,'passive_only':args.passive,'respect_robots':not args.ignore_robots,'exclusions':[],'allowed_hosts':[],'request_headers':{},'auth_cookies':None}); db.add(scan); db.commit(); db.refresh(scan)
    await ScanOrchestrator(db).run(scan); db.refresh(scan); print(f'[{scan.status.value}] {scan.id}\nHTML: reports/{scan.id}/report.html\nJSON: reports/{scan.id}/report.json')
def main():
    p=argparse.ArgumentParser(description='FIREWATCH authorized web security scanner'); p.add_argument('url'); p.add_argument('--pages',type=int,default=300); p.add_argument('--depth',type=int,default=8); p.add_argument('--endpoints',type=int,default=2000); p.add_argument('--delay',type=int,default=150); p.add_argument('--no-browser',action='store_true'); p.add_argument('--no-graphql',action='store_true'); p.add_argument('--passive',action='store_true'); p.add_argument('--ignore-robots',action='store_true'); args=p.parse_args(); asyncio.run(run(args))
if __name__=='__main__': main()
