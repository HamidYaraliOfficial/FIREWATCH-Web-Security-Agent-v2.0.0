from __future__ import annotations
import asyncio,time
from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping
import httpx
from .config import settings
from .scope import ScopePolicy
@dataclass
class HTTPObservation:
    requested_url:str; final_url:str; status_code:int; headers:dict[str,str]; body:str; elapsed_ms:float; content_type:str; body_sha256:str; error:str|None=None
class SafeHTTPClient:
    def __init__(self,scope:ScopePolicy,timeout:float|None=None,delay_ms:int|None=None,headers:Mapping[str,str]|None=None):
        self.scope=scope; self.timeout=timeout or settings.request_timeout_seconds; self.delay_ms=settings.request_delay_ms if delay_ms is None else delay_ms; self.headers=dict(headers or {}); self.client=None; self._last_request_at=0.0; self._lock=asyncio.Lock()
    async def __aenter__(self):
        base={'User-Agent':settings.user_agent,'Accept':'text/html,application/json,text/plain,application/xml,*/*'}; base.update(self.headers)
        self.client=httpx.AsyncClient(timeout=self.timeout,follow_redirects=False,headers=base,verify=True,trust_env=False); return self
    async def __aexit__(self,*_):
        if self.client: await self.client.aclose()
    async def _throttle(self):
        gap=max(0,self.delay_ms)/1000.0
        async with self._lock:
            elapsed=time.monotonic()-self._last_request_at
            if elapsed<gap: await asyncio.sleep(gap-elapsed)
            self._last_request_at=time.monotonic()
    async def request(self,method:str,url:str,headers:Mapping[str,str]|None=None,content:str|bytes|None=None)->HTTPObservation:
        if not self.client: raise RuntimeError('SafeHTTPClient must be used as an async context manager')
        clean=self.scope.validate_url(url); await self._throttle(); start=time.perf_counter()
        try:
            resp=await self.client.request(method.upper(),clean,headers=dict(headers or {}),content=content); elapsed=(time.perf_counter()-start)*1000; body=resp.text[:2_000_000]
            return HTTPObservation(clean,str(resp.url),resp.status_code,{k.lower():v for k,v in resp.headers.items()},body,round(elapsed,2),resp.headers.get('content-type',''),sha256(body.encode('utf-8','replace')).hexdigest())
        except Exception as exc:
            elapsed=(time.perf_counter()-start)*1000
            return HTTPObservation(clean,clean,0,{},'',round(elapsed,2),'',sha256(b'').hexdigest(),str(exc))
