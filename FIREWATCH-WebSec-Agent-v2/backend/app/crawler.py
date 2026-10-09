from __future__ import annotations
import re, asyncio
from collections import deque
from dataclasses import dataclass,field
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser
from bs4 import BeautifulSoup
from .config import settings
from .http_client import HTTPObservation,SafeHTTPClient
from .scope import ScopePolicy
@dataclass
class PageSnapshot:
    url:str; depth:int; observation:HTTPObservation; title:str|None; links:list[str]; forms:list[dict]; resources:list[str]; technologies:list[str]; mixed_content:list[str]=field(default_factory=list); js_endpoints:list[str]=field(default_factory=list); meta:dict=field(default_factory=dict)
class Crawler:
    def __init__(self,scope,max_pages,max_depth,delay_ms,respect_robots=True,max_endpoints=2000,headers=None): self.scope=scope; self.max_pages=max_pages; self.max_depth=max_depth; self.delay_ms=delay_ms; self.respect_robots=respect_robots; self.max_endpoints=max_endpoints; self.headers=headers or {}
    async def crawl(self)->list[PageSnapshot]:
        snapshots=[]; queue=deque([(self.scope.root_url,0)]); visited=set(); robots=await self._load_robots() if self.respect_robots else None
        async with SafeHTTPClient(self.scope,delay_ms=self.delay_ms,headers=self.headers) as client:
            while queue and len(snapshots)<self.max_pages:
                batch=[]
                while queue and len(batch)<settings.max_concurrency:
                    url,depth=queue.popleft()
                    if url in visited or depth>self.max_depth: continue
                    if robots is not None and not robots.can_fetch(settings.user_agent,url): continue
                    visited.add(url); batch.append((url,depth))
                if not batch: continue
                results=await asyncio.gather(*(client.request('GET',u) for u,_ in batch))
                for (url,depth),obs in zip(batch,results):
                    if obs.error: continue
                    snap=self._snapshot(url,depth,obs); snapshots.append(snap)
                    if depth>=self.max_depth or not self._is_html(obs.content_type): continue
                    for link in snap.links+snap.resources+snap.js_endpoints:
                        if len(visited)>=self.max_endpoints: break
                        if link not in visited: queue.append((link,depth+1))
                    if len(snapshots)>=self.max_pages: break
        return snapshots
    async def _load_robots(self):
        p=urlparse(self.scope.root_url); robots_url=f'{p.scheme}://{p.netloc}/robots.txt'
        try:
            async with SafeHTTPClient(self.scope,delay_ms=self.delay_ms,headers=self.headers) as client: obs=await client.request('GET',robots_url)
            if obs.error or obs.status_code>=400: return None
            rp=RobotFileParser(); rp.set_url(robots_url); rp.parse(obs.body.splitlines()); return rp
        except Exception: return None
    async def discover_sitemaps(self)->list[str]:
        p=urlparse(self.scope.root_url); candidates=set(); roots=[f'{p.scheme}://{p.netloc}/sitemap.xml',f'{p.scheme}://{p.netloc}/sitemap_index.xml']
        async with SafeHTTPClient(self.scope,delay_ms=self.delay_ms,headers=self.headers) as client:
            for u in roots:
                obs=await client.request('GET',u)
                if obs.error or obs.status_code>=400: continue
                for m in re.findall(r'<loc>\s*([^<]+?)\s*</loc>',obs.body,flags=re.I):
                    s=self.scope.join(u,m.strip())
                    if s: candidates.add(s)
        return sorted(candidates)[:self.max_endpoints]
    @staticmethod
    def _is_html(ct): return 'text/html' in ct.lower() or 'application/xhtml+xml' in ct.lower()
    def _snapshot(self,url,depth,obs):
        links=[];resources=[];forms=[];mixed=[];js_endpoints=[];title=None;tech=self._fingerprint(obs.headers,obs.body)
        if self._is_html(obs.content_type):
            soup=BeautifulSoup(obs.body,'html.parser'); title=soup.title.get_text(strip=True)[:500] if soup.title else None
            for tag in soup.find_all(['a','area']):
                v=tag.get('href'); safe=self.scope.join(url,v) if v else None
                if safe: links.append(safe); mixed += [safe] if url.startswith('https://') and safe.startswith('http://') else []
            for tag in soup.find_all(['script','img','link','iframe','source']):
                attr='src' if tag.name in {'script','img','iframe','source'} else 'href'; v=tag.get(attr); safe=self.scope.join(url,v) if v else None
                if safe: resources.append(safe)
                if v and v.startswith('http://') and url.startswith('https://'): mixed.append(v)
            for form in soup.find_all('form'):
                action=self.scope.join(url,form.get('action') or url) or url; method=(form.get('method') or 'GET').upper(); inputs=[]
                for inp in form.find_all(['input','textarea','select','button']): inputs.append({'name':inp.get('name'),'type':inp.get('type'),'value_present':inp.get('value') is not None})
                forms.append({'action':action,'method':method,'inputs':inputs})
            js_endpoints=self._extract_js_endpoints(obs.body)
        return PageSnapshot(url,depth,obs,title,list(dict.fromkeys(links))[:1000],forms[:200],list(dict.fromkeys(resources))[:1000],sorted(set(tech)),list(dict.fromkeys(mixed))[:100],list(dict.fromkeys(js_endpoints))[:500],{'cache_control':obs.headers.get('cache-control'),'content_length':len(obs.body),'server':obs.headers.get('server')})
    def _extract_js_endpoints(self,body):
        found=set(); patterns=[r'["\']((?:https?://|/)[^"\']{2,300})["\']',r'fetch\(\s*["\']([^"\']+)["\']',r'axios\.(?:get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']']
        for pattern in patterns:
            for m in re.findall(pattern,body,flags=re.I):
                c=m[0] if isinstance(m,tuple) else m; safe=self.scope.join(self.scope.root_url,c)
                if safe and any(t in c.lower() for t in ('/api','/graphql','/v1/','/v2/','/auth','/login','/users','/admin')): found.add(safe)
        return sorted(found)
    def _fingerprint(self,headers,body):
        h={k.lower():v.lower() for k,v in headers.items()}; out=[]; server=h.get('server',''); powered=h.get('x-powered-by','')
        for token,name in [('nginx','Nginx'),('apache','Apache'),('iis','IIS')]:
            if token in server: out.append(name)
        if 'uvicorn' in server or 'starlette' in powered: out.append('FastAPI/Starlette')
        if 'express' in powered: out.append('Express')
        if 'php' in powered or '.php' in body.lower(): out.append('PHP')
        if '__next_data__' in body or '/_next/' in body: out.append('Next.js')
        if 'wp-content' in body: out.append('WordPress')
        return sorted(set(out))
