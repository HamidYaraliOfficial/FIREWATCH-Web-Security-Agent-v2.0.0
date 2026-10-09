from __future__ import annotations
from datetime import datetime
from typing import Any
from pydantic import BaseModel,Field,HttpUrl,ConfigDict
from .models import ScanStatus,Severity,FindingStatus
class ScanCreate(BaseModel):
    target_url:HttpUrl; scope_acknowledged:bool=False; project_id:str|None=None
    max_pages:int=Field(300,ge=1,le=5000); max_depth:int=Field(8,ge=0,le=20); max_endpoints:int=Field(2000,ge=10,le=10000)
    request_delay_ms:int=Field(150,ge=0,le=10000); max_concurrency:int=Field(6,ge=1,le=20)
    enable_browser:bool=True; enable_api_introspection:bool=True; enable_zap:bool=False; passive_only:bool=False; respect_robots:bool=True
    exclusions:list[str]=Field(default_factory=list,max_length=200); allowed_hosts:list[str]=Field(default_factory=list,max_length=20)
    request_headers:dict[str,str]=Field(default_factory=dict); auth_cookies:str|None=None; authorization_profiles:list[dict[str,Any]]=Field(default_factory=list,max_length=10); notes:str|None=None
class ScanSummary(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:str;target_url:str;status:ScanStatus;created_at:datetime;started_at:datetime|None=None;finished_at:datetime|None=None;error:str|None=None
class ScanDetail(ScanSummary): config:dict[str,Any];pages_count:int=0;assets_count:int=0;findings_count:int=0;events_count:int=0
class FindingOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:str;rule_id:str;category:str;title:str;severity:Severity;confidence:float;risk_score:float;status:FindingStatus;endpoint:str;description:str;impact:str;remediation:str;references:list[Any];evidence_summary:str
class EventOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:str;phase:str;message:str;progress:float;created_at:datetime
class AssetOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:str;url:str;kind:str;method:str;status_code:int|None;content_type:str|None;source:str;authenticated:bool;metadata_json:dict[str,Any]
