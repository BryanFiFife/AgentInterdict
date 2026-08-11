import os,time,json,hmac,hashlib,tempfile
from pathlib import Path
from fastapi.testclient import TestClient

def test_db_lead_and_suppression(tmp_path):
    from commercial.db import DB
    d=DB(tmp_path/'x.db'); d.init(); d.add_lead('A@Example.com',consent=True,source='test'); assert not d.is_suppressed('a@example.com'); d.suppress('a@example.com','bounce'); assert d.is_suppressed('A@example.com')

def test_stripe_signature():
    from commercial.security import verify_stripe_signature
    payload=b'{}'; secret='whsec_test'; ts=int(time.time()); sig=hmac.new(secret.encode(),f'{ts}.'.encode()+payload,hashlib.sha256).hexdigest(); assert verify_stripe_signature(payload,f't={ts},v1={sig}',secret)
    assert not verify_stripe_signature(payload,f't={ts},v1=bad',secret)

def test_webhook_idempotency(tmp_path):
    from commercial.db import DB
    d=DB(tmp_path/'x.db'); d.init(); assert d.claim_event('stripe','evt_1',{}); assert not d.claim_event('stripe','evt_1',{})

def test_activation_key_prefix():
    from commercial.licensing import new_activation_key,activation_hash
    k=new_activation_key(); assert k.startswith('mgk_'); assert len(activation_hash(k))==64

def test_metrics(tmp_path):
    from commercial.db import DB
    d=DB(tmp_path/'x.db'); d.init(); d.add_lead('x@example.com'); assert d.metrics()['leads']==1
