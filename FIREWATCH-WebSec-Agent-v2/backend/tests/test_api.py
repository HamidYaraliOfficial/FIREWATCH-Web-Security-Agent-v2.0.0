from fastapi.testclient import TestClient
from app.main import app

def test_health():
    with TestClient(app) as client:
        r=client.get('/health'); assert r.status_code==200; assert r.json()['version']=='2.0.0'

def test_scope_ack_required():
    with TestClient(app) as client:
        r=client.post('/api/v1/scans',json={'target_url':'https://example.com/','scope_acknowledged':False})
        assert r.status_code==400
