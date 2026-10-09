from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlparse
from .http_client import SafeHTTPClient
from .scope import ScopePolicy
from .checks.base import FindingCandidate
from .models import Severity
@dataclass
class AuthProfile:
    name:str
    headers:dict[str,str]
async def review_authorization(scope:ScopePolicy,urls:list[str],profiles:list[AuthProfile],delay_ms:int=150):
    if len(profiles)<2: return []
    low=next((p for p in profiles if p.name.lower() in {'low','user','member','anonymous'}),profiles[-1]); high=next((p for p in profiles if p.name.lower() in {'high','admin','privileged'}),profiles[0])
    candidates=[u for u in urls if any(x in urlparse(u).path.lower() for x in ('/admin','/users/','/accounts/','/orders/','/profile','/settings','/management','/internal'))][:100]
    out=[]
    async with SafeHTTPClient(scope,delay_ms=delay_ms) as client:
        for url in candidates:
            h=await client.request('GET',url,headers=high.headers); l=await client.request('GET',url,headers=low.headers)
            if h.status_code in {200,206,304} and l.status_code in {200,206,304}:
                out.append(FindingCandidate('FW-AUTHZ-001','access-control','Authorization review candidate: lower-privilege profile can read sensitive-looking endpoint',Severity.MEDIUM,.68,url,'A supplied lower-privilege authorization profile received a successful response from a sensitive-looking endpoint that also returned successfully for a higher-privilege profile. This is a review candidate, not proof of an authorization flaw.','A broken access-control decision could expose privileged data or functionality.','Verify server-side authorization for this resource with a real least-privilege test account and inspect the returned object/data.',f'High profile: {h.status_code}; low profile: {l.status_code}.',evidence={'high_status':h.status_code,'low_status':l.status_code}))
    return out
