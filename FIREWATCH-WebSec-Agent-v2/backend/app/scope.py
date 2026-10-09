from __future__ import annotations
import ipaddress, socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlunparse
class ScopeViolation(ValueError): pass
@dataclass(frozen=True)
class ScopePolicy:
    root_url:str
    allowed_hosts:frozenset[str]
    excluded_prefixes:tuple[str,...]=field(default_factory=tuple)
    allow_private_targets:bool=False
    @classmethod
    def from_root(cls,root_url:str,exclusions:list[str]|None=None,allow_private_targets:bool=False,allowed_hosts:list[str]|None=None):
        parsed=urlparse(str(root_url).strip())
        if parsed.scheme not in {'http','https'} or not parsed.hostname: raise ScopeViolation('Target must be an absolute HTTP(S) URL')
        host=parsed.hostname.lower().rstrip('.')
        port=parsed.port
        netloc=f'{host}:{port}' if port else host
        normalized=urlunparse((parsed.scheme.lower(),netloc,parsed.path or '/', '', parsed.query,''))
        hosts={host}
        for item in allowed_hosts or []:
            item=item.strip().lower().rstrip('.')
            if item: hosts.add(item.split(':',1)[0])
        obj=cls(normalized,frozenset(hosts),tuple(exclusions or ()),allow_private_targets)
        if not allow_private_targets: obj._reject_private_host(host)
        return obj
    @staticmethod
    def _reject_private_host(host:str):
        try: infos=socket.getaddrinfo(host,None)
        except socket.gaierror: return
        for info in infos:
            try: ip=ipaddress.ip_address(info[4][0])
            except ValueError: continue
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                raise ScopeViolation('Private, loopback, link-local, reserved, or multicast targets are disabled by policy')
    def is_allowed(self,url:str)->bool:
        try:
            parsed=urlparse(url); host=(parsed.hostname or '').lower().rstrip('.')
            if parsed.scheme not in {'http','https'} or host not in self.allowed_hosts: return False
            path=parsed.path or '/'
            return not any(path.startswith(p) for p in self.excluded_prefixes)
        except Exception: return False
    def validate_url(self,url:str)->str:
        parsed=urlparse(str(url))
        if parsed.scheme not in {'http','https'} or not parsed.hostname: raise ScopeViolation('Only absolute HTTP(S) URLs are allowed')
        host=parsed.hostname.lower().rstrip('.')
        if host not in self.allowed_hosts: raise ScopeViolation(f'Host outside configured scope: {host}')
        path=parsed.path or '/'
        if any(path.startswith(p) for p in self.excluded_prefixes): raise ScopeViolation(f'Path excluded by scope policy: {path}')
        if not self.allow_private_targets: self._reject_private_host(host)
        return urlunparse((parsed.scheme.lower(),parsed.netloc,path,'',parsed.query,''))
    def join(self,base:str,value:str)->str|None:
        try: return self.validate_url(urljoin(base,value))
        except Exception: return None
