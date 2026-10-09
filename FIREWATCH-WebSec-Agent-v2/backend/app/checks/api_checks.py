from __future__ import annotations
import json,re
from urllib.parse import urlparse
from .base import FindingCandidate,CheckContext
from ..models import Severity

SPEC_PATHS=('/openapi.json','/openapi.yaml','/swagger.json','/swagger/v1/swagger.json','/api-docs','/v3/api-docs','/docs/openapi.json')

def classify_api(url):
    p=urlparse(url).path.lower()
    return 'graphql' if 'graphql' in p else 'api' if any(x in p for x in ('/api/','/v1/','/v2/','/rest/')) else 'web'

def run_openapi_checks(spec_url,body,content_type):
    out=[]
    try:
        data=json.loads(body)
    except Exception: return out
    if not isinstance(data,dict) or not ('openapi' in data or 'swagger' in data): return out
    paths=data.get('paths',{}) if isinstance(data.get('paths',{}),dict) else {}
    if not paths: out.append(FindingCandidate('FW-API-001','api-inventory','API specification has no paths',Severity.INFO,.95,spec_url,'The published API specification contains no paths.','The documentation may be incomplete or stale.','Keep API inventory synchronized with deployed routes.','No paths entry in published specification.'))
    for p,item in paths.items():
        if not isinstance(item,dict): continue
        methods={m.lower() for m in item.keys() if m.lower() in {'get','post','put','patch','delete','options','head'}}
        for m in methods:
            op=item[m]
            if isinstance(op,dict) and not op.get('security') and not data.get('components',{}).get('securitySchemes') and not data.get('security'):
                out.append(FindingCandidate('FW-API-002','api-authentication','API operation appears undocumented as authenticated',Severity.MEDIUM,.72,spec_url,f'{m.upper()} {p} has no security requirement and the spec has no global security declaration.','Sensitive APIs may be unintentionally exposed.','Verify whether the operation is intentionally public; document and enforce authentication where required.',f'Operation {m.upper()} {p} has no security declaration.',evidence={'path':p,'method':m}))
                break
    return out

def run_graphql_observation(url,body):
    if 'graphql' not in url.lower(): return []
    return [FindingCandidate('FW-GQL-001','graphql','GraphQL endpoint discovered',Severity.INFO,.98,url,'A GraphQL endpoint appears to be exposed.','GraphQL deserves dedicated authorization, depth/complexity, and introspection review.','Review schema exposure, resolver authorization, query complexity controls, and introspection policy.',f'GraphQL-like URL discovered: {url}')]

def candidate_api_paths(root):
    from urllib.parse import urljoin
    return [urljoin(root,x) for x in SPEC_PATHS]
