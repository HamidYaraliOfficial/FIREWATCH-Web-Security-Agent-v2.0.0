from __future__ import annotations
import ssl,socket
from urllib.parse import urlparse
from .base import FindingCandidate
from ..models import Severity

def inspect_tls(url):
    out=[]; p=urlparse(url)
    if p.scheme!='https': return out
    try:
        ctx=ssl.create_default_context(); ctx.check_hostname=True
        with socket.create_connection((p.hostname,p.port or 443),timeout=5) as raw:
            with ctx.wrap_socket(raw,server_hostname=p.hostname) as s:
                cert=s.getpeercert(); version=s.version(); cipher=s.cipher()[0] if s.cipher() else None
        if version not in {'TLSv1.3','TLSv1.2'}: out.append(FindingCandidate('FW-TLS-001','transport','Unexpected TLS protocol version',Severity.MEDIUM,.98,url,f'TLS connection negotiated {version}.','Legacy protocol versions can provide weaker cryptographic guarantees.','Restrict service-side TLS to modern protocol versions.',f'Negotiated {version}.'))
        if cipher and any(x in cipher.upper() for x in ('RC4','3DES','NULL','EXPORT')): out.append(FindingCandidate('FW-TLS-002','transport','Weak TLS cipher negotiated',Severity.HIGH,.98,url,f'The scanner negotiated cipher {cipher}.','Weak cryptographic suites may reduce transport security.','Disable legacy/weak cipher suites at the edge.',f'Negotiated cipher: {cipher}.'))
    except Exception as exc:
        out.append(FindingCandidate('FW-TLS-003','transport','TLS inspection failed',Severity.INFO,.95,url,'The agent could not complete a direct TLS handshake inspection from its runtime.','Transport posture could not be fully evaluated.', 'Run TLS assessment from a network position that can resolve and reach the target.',f'TLS inspection error: {type(exc).__name__}: {exc}'))
    return out
