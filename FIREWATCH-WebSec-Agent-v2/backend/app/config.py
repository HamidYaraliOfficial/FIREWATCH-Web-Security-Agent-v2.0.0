from __future__ import annotations
from dataclasses import dataclass
import os

def _bool(name: str, default: bool) -> bool:
    value=os.getenv(name)
    if value is None: return default
    return value.strip().lower() in {'1','true','yes','on'}
def _int(name: str, default: int) -> int:
    try: return int(os.getenv(name,str(default)))
    except ValueError: return default
def _float(name: str, default: float) -> float:
    try: return float(os.getenv(name,str(default)))
    except ValueError: return default
@dataclass(frozen=True)
class Settings:
    app_name:str=os.getenv('APP_NAME','FIREWATCH Web Security Agent')
    environment:str=os.getenv('ENVIRONMENT','development')
    database_url:str=os.getenv('DATABASE_URL','sqlite:///./firewatch.db')
    allow_private_targets:bool=_bool('ALLOW_PRIVATE_TARGETS',False)
    require_scope_ack:bool=_bool('REQUIRE_SCOPE_ACK',True)
    max_pages:int=_int('MAX_PAGES',300)
    max_depth:int=_int('MAX_DEPTH',8)
    max_endpoints:int=_int('MAX_ENDPOINTS',2000)
    request_timeout_seconds:float=_float('REQUEST_TIMEOUT_SECONDS',15.0)
    browser_timeout_seconds:float=_float('BROWSER_TIMEOUT_SECONDS',30.0)
    request_delay_ms:int=_int('REQUEST_DELAY_MS',150)
    max_concurrency:int=_int('MAX_CONCURRENCY',6)
    respect_robots:bool=_bool('RESPECT_ROBOTS',True)
    enable_browser:bool=_bool('ENABLE_BROWSER',True)
    enable_api_introspection:bool=_bool('ENABLE_API_INTROSPECTION',True)
    enable_zap:bool=_bool('ENABLE_ZAP',False)
    zap_base_url:str=os.getenv('ZAP_BASE_URL','http://zap:8080')
    report_dir:str=os.getenv('REPORT_DIR','./reports')
    user_agent:str=os.getenv('USER_AGENT','FIREWATCH-WebSec-Agent/2.0 (+authorized-security-testing)')
    cors_origins:str=os.getenv('CORS_ORIGINS','http://localhost:8000,http://127.0.0.1:8000')
    log_level:str=os.getenv('LOG_LEVEL','INFO')
settings=Settings()
