from __future__ import annotations
import logging, asyncio
from datetime import datetime,timezone
from pathlib import Path
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .browser import BrowserDiscovery
from .config import settings
from .crawler import Crawler
from .evidence import normalize_candidate
from .models import Asset, Evidence, Finding, Page, Report, Scan, ScanEvent, ScanStatus
from .risk import calculate_risk
from .scope import ScopePolicy
from .checks.registry import run_page_rules
from .checks.network_checks import inspect_tls
from .api_discovery import APIDiscovery
from .authz import AuthProfile, review_authorization
from .report import render,render_json
from .zap import ZAPAdapter
logger=logging.getLogger(__name__)
def utcnow(): return datetime.now(timezone.utc)
class ScanOrchestrator:
    def __init__(self,db:Session): self.db=db
    def event(self,scan,phase,message,progress):
        self.db.add(ScanEvent(scan_id=scan.id,phase=phase,message=message,progress=float(progress))); self.db.commit()
    def _headers(self,config):
        headers=dict(config.get('request_headers') or {})
        cookies=config.get('auth_cookies')
        if cookies and 'cookie' not in {k.lower() for k in headers}: headers['Cookie']=cookies
        return headers
    async def run(self,scan:Scan)->None:
        scan.status=ScanStatus.RUNNING; scan.started_at=utcnow(); self.db.commit()
        config=scan.config or {}; headers=self._headers(config)
        try:
            self.event(scan,'scope','Validating scope and scan policy',2)
            policy=ScopePolicy.from_root(scan.target_url,exclusions=config.get('exclusions',[]),allow_private_targets=settings.allow_private_targets,allowed_hosts=config.get('allowed_hosts',[]))
            if config.get('passive_only'): self.event(scan,'policy','Passive-only mode enabled; no active API introspection/browser workflows will be run',4)
            self.event(scan,'recon','Crawling target and building attack-surface inventory',8)
            crawler=Crawler(policy,max_pages=int(config.get('max_pages',settings.max_pages)),max_depth=int(config.get('max_depth',settings.max_depth)),delay_ms=int(config.get('request_delay_ms',settings.request_delay_ms)),respect_robots=bool(config.get('respect_robots',settings.respect_robots)),max_endpoints=int(config.get('max_endpoints',settings.max_endpoints)),headers=headers)
            pages=await crawler.crawl(); self.event(scan,'recon',f'Discovered {len(pages)} web pages/resources',28)
            for page in pages:
                self.db.add(Page(scan_id=scan.id,url=page.url,method='GET',status_code=page.observation.status_code,content_type=page.observation.content_type,title=page.title,depth=page.depth,headers=self._safe_headers(page.observation.headers),links=page.links,resources=page.resources,technologies=page.technologies,body_sha256=page.observation.body_sha256))
                self._asset(scan,page.url,'page',page.observation.status_code,page.observation.content_type,'crawler',{'depth':page.depth,'title':page.title,'technologies':page.technologies})
                for u in page.resources[:500]: self._asset(scan,u,'resource',None,None,'crawler',{})
                for u in page.js_endpoints[:500]: self._asset(scan,u,'js-api-candidate',None,None,'js-analysis',{})
                for candidate in run_page_rules(page,{'target':scan.target_url}): self._store_finding(scan,candidate)
            profiles=[AuthProfile(str(x.get('name','profile')),dict(x.get('headers') or {})) for x in (config.get('authorization_profiles') or []) if isinstance(x,dict)]
            if len(profiles)>=2:
                authz_findings=await review_authorization(policy,[p.url for p in pages],profiles,delay_ms=int(config.get('request_delay_ms',settings.request_delay_ms)))
                for candidate in authz_findings: self._store_finding(scan,candidate)
            self.db.commit()
            self.event(scan,'api','Discovering API specifications, GraphQL endpoints and OPTIONS/CORS posture',40)
            api=APIDiscovery(policy,delay_ms=int(config.get('request_delay_ms',settings.request_delay_ms)),headers=headers,max_endpoints=int(config.get('max_endpoints',settings.max_endpoints)))
            assets,api_findings,specs=await api.run()
            for url,kind,status,ct,meta in assets: self._asset(scan,url,kind,status,ct,'api-discovery',meta)
            for candidate in api_findings:self._store_finding(scan,candidate)
            if config.get('enable_api_introspection',settings.enable_api_introspection) and not config.get('passive_only'):
                graphqls=[x[0] for x in assets if x[1]=='graphql'][:10]
                for endpoint in graphqls:
                    result=await api.graphql_introspection(endpoint)
                    if result:
                        obs,data=result
                        types=data.get('data',{}).get('__schema',{}).get('types',[]) if isinstance(data,dict) else []
                        if types:
                            self._asset(scan,endpoint,'graphql-schema',obs.status_code,obs.content_type,'graphql-introspection',{'type_count':len(types)})
                            self._store_finding(scan,__import__('backend.app.checks.base',fromlist=['FindingCandidate']).FindingCandidate('FW-GQL-002','graphql','GraphQL introspection enabled',__import__('backend.app.models',fromlist=['Severity']).Severity.LOW,.97,endpoint,'GraphQL introspection returned a schema to the supplied security-testing session.','Public schema exposure can simplify discovery of API capabilities.','Disable introspection in production when it is not required, or restrict it to trusted development/admin contexts.','Introspection query returned a schema.',evidence={'type_count':len(types)}))
                        else: self._asset(scan,endpoint,'graphql-endpoint',obs.status_code,obs.content_type,'graphql-introspection',{})
            self.db.commit(); self.event(scan,'transport','Inspecting TLS and redirect posture',58)
            for candidate in inspect_tls(scan.target_url): self._store_finding(scan,candidate)
            await self._redirect_checks(scan,policy,headers)
            self.event(scan,'metadata','Checking standard metadata and operational security endpoints',66)
            await self._metadata_checks(scan,policy,headers)
            if config.get('enable_browser',settings.enable_browser) and not config.get('passive_only'):
                self.event(scan,'browser','Running same-origin browser discovery (no form submission)',75)
                try:
                    br=await BrowserDiscovery(policy,headers=headers).discover()
                    for u in br.resources: self._asset(scan,u,'browser-resource',None,None,'browser',{})
                    for u in br.requests: self._asset(scan,u,'browser-request',None,None,'browser',{})
                    for u in br.links: self._asset(scan,u,'browser-link',None,None,'browser',{})
                    if br.storage_keys: self._asset(scan,scan.target_url,'browser-storage',None,None,'browser',{'keys':br.storage_keys})
                    if br.cookies:
                        self._asset(scan,scan.target_url,'browser-cookies',None,None,'browser',{'count':len(br.cookies),'names':[c.get('name') for c in br.cookies[:100]]})
                except Exception as exc: self.event(scan,'browser',f'Browser discovery skipped: {type(exc).__name__}',84)
            if config.get('enable_zap') and not config.get('passive_only'):
                self.event(scan,'zap','Preparing optional OWASP ZAP passive automation plan',88)
                try:
                    zap=ZAPAdapter(settings.zap_base_url,workdir=str(Path(settings.report_dir)/scan.id/'zap'))
                    plan=zap.write_plan(scan.target_url)
                    self._asset(scan,scan.target_url,'zap-plan',None,None,'zap',{'plan_path':plan.plan_path,'reachable':zap.health()})
                except Exception as exc:
                    self.event(scan,'zap',f'ZAP adapter skipped: {type(exc).__name__}',89)
            self.event(scan,'finalize','Deduplicating findings and rendering reports',90)
            scan.status=ScanStatus.COMPLETED; scan.finished_at=utcnow(); self.db.commit(); await self._write_reports(scan,pages); self.event(scan,'complete','Scan completed',100)
        except Exception as exc:
            logger.exception('scan failed'); scan.status=ScanStatus.FAILED; scan.error=str(exc); scan.finished_at=utcnow(); self.db.commit(); raise
    def _safe_headers(self,h): return {k:('[REDACTED]' if k in {'authorization','cookie','set-cookie','x-api-key'} else v) for k,v in h.items()}
    def _asset(self,scan,url,kind,status,ct,source,meta):
        if self.db.scalar(select(Asset.id).where(Asset.scan_id==scan.id,Asset.url==url,Asset.kind==kind)) is None: self.db.add(Asset(scan_id=scan.id,url=url,kind=kind,status_code=status,content_type=ct,source=source,authenticated=bool(scan.config.get('auth_cookies') or scan.config.get('request_headers')),metadata_json=meta))
    def _store_finding(self,scan,c):
        n=normalize_candidate(c)
        if self.db.scalar(select(Finding.id).where(Finding.scan_id==scan.id,Finding.dedupe_key==n.dedupe_key)): return
        f=Finding(scan_id=scan.id,rule_id=c.rule_id,category=c.category,title=c.title,severity=c.severity,confidence=max(0,min(1,c.confidence)),risk_score=calculate_risk(c.severity,c.confidence),endpoint=c.endpoint,description=c.description,impact=c.impact,remediation=c.remediation,references=c.references,evidence_summary=c.evidence_summary,dedupe_key=n.dedupe_key)
        self.db.add(f); self.db.flush(); self.db.add(Evidence(finding_id=f.id,kind='observation',data=c.evidence or {'summary':c.evidence_summary}))
    async def _redirect_checks(self,scan,policy,headers):
        from .http_client import SafeHTTPClient
        async with SafeHTTPClient(policy,delay_ms=int(scan.config.get('request_delay_ms',settings.request_delay_ms)),headers=headers) as client:
            obs=await client.request('GET',scan.target_url)
        loc=obs.headers.get('location') if obs else None
        if loc and scan.target_url.startswith('https://') and loc.startswith('http://'):
            from .checks.base import FindingCandidate
            from .models import Severity
            self._store_finding(scan,FindingCandidate('FW-TRANSPORT-001','transport','HTTPS redirects to HTTP',Severity.HIGH,.99,scan.target_url,'The target advertises a cleartext HTTP redirect destination.','A user can be downgraded to cleartext transport if they follow the redirect.','Keep canonical redirects on HTTPS and prevent cleartext downgrade paths.','Location header points from HTTPS to HTTP.',evidence={'location':loc}))
    async def _metadata_checks(self,scan,policy,headers):
        from .http_client import SafeHTTPClient
        async with SafeHTTPClient(policy,delay_ms=int(scan.config.get('request_delay_ms',settings.request_delay_ms)),headers=headers) as client:
            p=urlparse(scan.target_url); base=f'{p.scheme}://{p.netloc}'
            for path in ('/.well-known/security.txt','/security.txt','/robots.txt','/sitemap.xml'):
                u=base+path; obs=await client.request('GET',u)
                if not obs.error and 200<=obs.status_code<400:
                    kind='security.txt' if 'security.txt' in path else path.lstrip('/')
                    self._asset(scan,u,kind,obs.status_code,obs.content_type,'metadata',{'length':len(obs.body)})
            # CORS reflection check using a synthetic untrusted origin; read-only GET only.
            probe_origin='https://firewatch.invalid'
            obs=await client.request('GET',scan.target_url,headers={'Origin':probe_origin})
            if obs.headers.get('access-control-allow-origin')==probe_origin:
                from .checks.base import FindingCandidate
                from .models import Severity
                self._store_finding(scan,FindingCandidate('FW-CORS-004','api','CORS origin reflection detected',Severity.MEDIUM,.9,scan.target_url,'The response reflected an arbitrary test Origin value in Access-Control-Allow-Origin.','Origin reflection can enable unintended cross-origin access when combined with sensitive resources or credentials.','Use a strict allow-list and validate origins server-side rather than reflecting arbitrary Origin values.','Injected test Origin was reflected.',evidence={'test_origin':probe_origin}))
    async def _write_reports(self,scan,pages):
        report_dir=Path(settings.report_dir)/scan.id; report_dir.mkdir(parents=True,exist_ok=True)
        findings=list(self.db.scalars(select(Finding).where(Finding.scan_id==scan.id).order_by(Finding.risk_score.desc()))); events=list(self.db.scalars(select(ScanEvent).where(ScanEvent.scan_id==scan.id).order_by(ScanEvent.created_at.asc())))
        coverage=[{'phase':e.phase,'status':'completed' if e.progress>=100 else 'observed','details':e.message} for e in events]
        html=str(report_dir/'report.html'); js=str(report_dir/'report.json'); render(scan,findings,events,html,coverage); render_json(scan,findings,events,js,coverage)
        self.db.query(Report).filter(Report.scan_id==scan.id).delete(synchronize_session=False); self.db.add_all([Report(scan_id=scan.id,format='html',path=html),Report(scan_id=scan.id,format='json',path=js)]); self.db.commit()
from urllib.parse import urlparse
