from __future__ import annotations
from .base import FindingCandidate,CheckContext
from ..models import Severity

def _cookies(raw):
    if not raw:return []
    return [x.strip() for x in raw.split(',') if x.strip()]
def run_cookie_checks(page,context):
    out=[]; raw=page.observation.headers.get('set-cookie')
    for cookie in _cookies(raw):
        name=cookie.split('=',1)[0].strip(); low=cookie.lower(); session=any(x in name.lower() for x in ('session','sess','auth','token','jwt','sid'))
        if page.url.startswith('https://') and 'secure' not in low: out.append(FindingCandidate('FW-COOKIE-001','session','Cookie missing Secure attribute',Severity.MEDIUM if session else Severity.LOW,.96,page.url,f'Cookie `{name}` lacks Secure.','Browser may transmit it over non-HTTPS contexts.','Add Secure to cookies that are intended for HTTPS-only transport.',f'{name}: Secure absent.',evidence={'cookie':name}))
        if session and 'httponly' not in low: out.append(FindingCandidate('FW-COOKIE-002','session','Session-like cookie missing HttpOnly',Severity.MEDIUM,.95,page.url,f'Cookie `{name}` appears session/auth related but lacks HttpOnly.','Client-side script access can increase credential exposure in case of XSS.','Add HttpOnly when JavaScript access is not required.',f'{name}: HttpOnly absent.',evidence={'cookie':name}))
        if 'samesite=' not in low: out.append(FindingCandidate('FW-COOKIE-003','session','Cookie missing SameSite attribute',Severity.LOW,.9,page.url,f'Cookie `{name}` does not explicitly declare SameSite.','Cross-site cookie behavior is less explicit.','Set SameSite=Lax/Strict as appropriate, using None only when required and with Secure.',f'{name}: SameSite absent.',evidence={'cookie':name}))
    return out
