import json,time,html
from .config import settings
from .db import DB
from .providers import ResendProvider,StripeProvider

def process(limit=25):
    db=DB(settings.db_path); db.init(); now=int(time.time())
    with db.conn() as c: jobs=c.execute("SELECT * FROM jobs WHERE status='queued' AND run_after<=? ORDER BY id LIMIT ?",(now,limit)).fetchall()
    for job in jobs:
        payload=json.loads(job['payload']); ok=False; err=''
        try:
            if db.is_suppressed(payload.get('email','')): ok=True
            elif job['kind']=='send_activation':
                ResendProvider(settings.resend_api_key,settings.email_from).send(payload['email'],'Your MemoryGuard activation key',f"<p>Your activation key:</p><pre>{html.escape(payload['activation_key'])}</pre>"); ok=True
            elif job['kind']=='payment_failed':
                ResendProvider(settings.resend_api_key,settings.email_from).send(payload['email'],'MemoryGuard payment issue','<p>Your subscription payment needs attention. Please use the billing portal.</p>'); ok=True
            elif job['kind']=='billing_portal':
                url=StripeProvider(settings.stripe_secret_key).portal(payload['stripe_customer_id'],settings.public_url)['url']
                ResendProvider(settings.resend_api_key,settings.email_from).send(payload['email'],'Manage your MemoryGuard subscription',f'<p><a href="{html.escape(url)}">Open secure billing portal</a></p>'); ok=True
        except Exception as e: err=str(e)[:500]
        with db.conn() as c:
            if ok: c.execute("UPDATE jobs SET status='done',updated_at=? WHERE id=?",(int(time.time()),job['id']))
            else:
                attempts=job['attempts']+1; delay=min(3600,30*(2**min(attempts,6)))
                c.execute("UPDATE jobs SET attempts=?,run_after=?,last_error=?,updated_at=? WHERE id=?",(attempts,int(time.time())+delay,err,int(time.time()),job['id']))
    return len(jobs)
if __name__=='__main__': print(process())
