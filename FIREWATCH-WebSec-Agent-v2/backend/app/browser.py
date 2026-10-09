from __future__ import annotations
from dataclasses import dataclass, field
import importlib.util
from urllib.parse import urlparse
from .config import settings
from .scope import ScopePolicy
@dataclass
class BrowserResult:
    url:str
    links:list[str]
    resources:list[str]
    title:str|None
    technologies:list[str]
    requests:list[str]=field(default_factory=list)
    cookies:list[dict]=field(default_factory=list)
    storage_keys:list[str]=field(default_factory=list)
    forms:list[dict]=field(default_factory=list)
class BrowserDiscovery:
    def __init__(self,scope:ScopePolicy,headers:dict[str,str]|None=None): self.scope=scope; self.headers=headers or {}
    async def discover(self)->BrowserResult:
        if importlib.util.find_spec('playwright') is None: raise RuntimeError('Playwright is not installed')
        from playwright.async_api import async_playwright
        requests=[]
        async with async_playwright() as pw:
            browser=await pw.chromium.launch(headless=True)
            context=await browser.new_context(ignore_https_errors=False,user_agent=settings.user_agent,extra_http_headers=self.headers)
            page=await context.new_page()
            def record(req):
                try:
                    if self.scope.is_allowed(req.url): requests.append(req.url)
                except Exception: pass
            page.on('request',record)
            async def guard(route):
                u=route.request.url
                scheme=urlparse(u).scheme.lower()
                if scheme in {'data','blob','about'} or self.scope.is_allowed(u): await route.continue_()
                else: await route.abort()
            await page.route('**/*',guard)
            await page.goto(self.scope.root_url,wait_until='domcontentloaded',timeout=int(settings.browser_timeout_seconds*1000))
            await page.wait_for_timeout(500)
            links=await page.locator('a[href]').evaluate_all("els => els.map(e => e.href)")
            resources=await page.locator('script[src],img[src],link[href],iframe[src]').evaluate_all("els => els.map(e => e.src || e.href)")
            forms=await page.locator('form').evaluate_all("forms => forms.map(f => ({action:f.action,method:(f.method||'GET').toUpperCase(),inputs:[...f.querySelectorAll('input,textarea,select,button')].map(i=>({name:i.name,type:i.type}) )}))")
            safe_links=[x for x in (self.scope.join(self.scope.root_url,u) for u in links) if x]
            safe_resources=[x for x in (self.scope.join(self.scope.root_url,u) for u in resources) if x]
            safe_requests=[x for x in requests if self.scope.is_allowed(x)]
            storage=await page.evaluate("() => [...Object.keys(localStorage), ...Object.keys(sessionStorage)]")
            cookies=await context.cookies()
            scripts=' '.join(safe_resources+safe_requests)
            tech=[]
            if '/_next/' in scripts: tech.append('Next.js')
            if 'react' in scripts.lower(): tech.append('React')
            if 'vue' in scripts.lower(): tech.append('Vue')
            result=BrowserResult(self.scope.root_url,list(dict.fromkeys(safe_links))[:1000],list(dict.fromkeys(safe_resources))[:1000],await page.title(),sorted(set(tech)),list(dict.fromkeys(safe_requests))[:2000],cookies[:200],sorted(set(storage))[:500],forms[:200])
            await context.close(); await browser.close()
            return result
