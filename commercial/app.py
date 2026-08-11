import json,os
from fastapi import FastAPI,Request,HTTPException,Header
from pydantic import BaseModel,EmailStr,Field
from .config import settings
from .db import DB
from .security import verify_stripe_signature,verify_svix
from .service import CommercialService
from .providers import StripeProvider

db=DB(settings.db_path); db.init(); service=CommercialService(db,settings)
app=FastAPI(title='MemoryGuard Commercial Control Plane',version='0.4')

class Lead(BaseModel):
    email: EmailStr; name:str|None=None; source:str|None=None; campaign:str|None=None; consent:bool=False
class Checkout(BaseModel):
    price_id:str=Field(min_length=3); email:EmailStr|None=None
class BillingLink(BaseModel): email:EmailStr

def operator(k):
    if not settings.operator_key or k!=settings.operator_key: raise HTTPException(401,'unauthorized')

@app.get('/health')
def health(): return {'ok':True}
@app.post('/api/leads')
def lead(x:Lead): db.add_lead(str(x.email),x.name,x.source,x.campaign,x.consent); return {'ok':True}
@app.post('/api/checkout')
def checkout(x:Checkout):
    if not settings.stripe_secret_key: raise HTTPException(503,'billing not configured')
    s=StripeProvider(settings.stripe_secret_key).checkout(x.price_id,settings.public_url+'/success',settings.public_url+'/pricing',str(x.email) if x.email else None)
    return {'url':s['url']}
@app.post('/api/billing-link')
def billing(x:BillingLink):
    # Enumeration-safe response; actual portal link is emailed via durable queue.
    with db.conn() as c: row=c.execute('SELECT stripe_customer_id FROM customers WHERE email=?',(str(x.email).lower(),)).fetchone()
    if row and row['stripe_customer_id']: db.queue('billing_portal',{'email':str(x.email),'stripe_customer_id':row['stripe_customer_id']})
    return {'ok':True}
@app.post('/webhooks/stripe')
async def stripe_hook(req:Request,stripe_signature:str|None=Header(None,alias='Stripe-Signature')):
    body=await req.body()
    if len(body)>1024*1024: raise HTTPException(413,'too large')
    if not verify_stripe_signature(body,stripe_signature or '',settings.stripe_webhook_secret): raise HTTPException(400,'bad signature')
    event=json.loads(body); eid=event.get('id')
    if not eid: raise HTTPException(400,'missing event id')
    if not db.claim_event('stripe',eid,event): return {'ok':True,'duplicate':True}
    try: service.stripe_event(event); db.finish_event('stripe',eid); return {'ok':True}
    except Exception: db.finish_event('stripe',eid,'failed'); raise
@app.post('/webhooks/resend')
async def resend_hook(req:Request,svix_id:str|None=Header(None),svix_timestamp:str|None=Header(None),svix_signature:str|None=Header(None)):
    body=await req.body();
    if len(body)>1024*1024: raise HTTPException(413,'too large')
    if not verify_svix(body,svix_id or '',svix_timestamp or '',svix_signature or '',settings.resend_webhook_secret): raise HTTPException(400,'bad signature')
    event=json.loads(body); eid=svix_id
    if not db.claim_event('resend',eid,event): return {'ok':True,'duplicate':True}
    typ=event.get('type',''); data=event.get('data') or {}; recipients=data.get('to') or []
    if typ in ('email.bounced','email.complained'):
        for e in recipients: db.suppress(e,typ)
    db.finish_event('resend',eid); return {'ok':True}

@app.post('/api/cron/process')
def cron_process(x_cron_secret:str|None=Header(None,alias='X-Cron-Secret')):
    if not settings.cron_secret or x_cron_secret!=settings.cron_secret: raise HTTPException(401,'unauthorized')
    from .worker import process
    return {'processed':process()}

@app.get('/api/admin/metrics')
def metrics(x_operator_key:str|None=Header(None,alias='X-Operator-Key')): operator(x_operator_key); return db.metrics()
