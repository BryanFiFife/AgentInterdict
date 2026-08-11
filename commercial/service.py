import json,time,secrets
from .licensing import new_activation_key,activation_hash

class CommercialService:
    def __init__(self,db,settings): self.db=db; self.settings=settings
    def ensure_customer(self,email,name=None,stripe_customer_id=None):
        n=self.db.now()
        with self.db.conn() as c:
            c.execute('''INSERT INTO customers(email,name,stripe_customer_id,created_at,updated_at) VALUES(?,?,?,?,?)
            ON CONFLICT(email) DO UPDATE SET name=COALESCE(excluded.name,name),stripe_customer_id=COALESCE(excluded.stripe_customer_id,stripe_customer_id),updated_at=excluded.updated_at''',(email.lower(),name,stripe_customer_id,n,n))
            return c.execute('SELECT * FROM customers WHERE email=?',(email.lower(),)).fetchone()
    def subscription_update(self,obj):
        customer=obj.get('customer'); sid=obj.get('id'); status=obj.get('status'); price=((obj.get('items') or {}).get('data') or [{}])[0].get('price',{}).get('id')
        tier='pro' if status in ('active','trialing') else 'community'; n=self.db.now()
        with self.db.conn() as c:
            row=c.execute('SELECT id FROM customers WHERE stripe_customer_id=?',(customer,)).fetchone()
            if row: c.execute('UPDATE customers SET subscription_id=?,subscription_status=?,tier=?,updated_at=? WHERE id=?',(sid,status,tier,n,row['id']))
    def checkout_completed(self,obj):
        email=((obj.get('customer_details') or {}).get('email') or obj.get('customer_email'))
        if not email: return
        row=self.ensure_customer(email,stripe_customer_id=obj.get('customer'))
        key=new_activation_key()
        with self.db.conn() as c:
            exists=c.execute('SELECT 1 FROM licenses WHERE customer_id=? AND revoked=0',(row['id'],)).fetchone()
            if not exists: c.execute('INSERT INTO licenses(customer_id,activation_key_hash,tier,created_at) VALUES(?,?,?,?)',(row['id'],activation_hash(key),'pro',self.db.now()))
        self.db.queue('send_activation',{'email':email,'activation_key':key})
    def entitlement_update(self,obj):
        cust=obj.get('customer'); active=obj.get('entitlements',{}).get('data',[]) if isinstance(obj.get('entitlements'),dict) else obj.get('active_entitlements',[])
        with self.db.conn() as c:
            row=c.execute('SELECT id FROM customers WHERE stripe_customer_id=?',(cust,)).fetchone()
            if not row: return
            cid=row['id']; c.execute('UPDATE entitlements SET active=0,updated_at=? WHERE customer_id=?',(self.db.now(),cid))
            for e in active:
                feature=(e.get('lookup_key') or e.get('feature') or e.get('id')) if isinstance(e,dict) else str(e)
                c.execute('INSERT INTO entitlements(customer_id,feature,active,updated_at) VALUES(?,?,1,?) ON CONFLICT(customer_id,feature) DO UPDATE SET active=1,updated_at=excluded.updated_at',(cid,feature,self.db.now()))
    def stripe_event(self,event):
        t=event.get('type',''); obj=(event.get('data') or {}).get('object') or {}
        if t=='checkout.session.completed': self.checkout_completed(obj)
        elif t.startswith('customer.subscription.'): self.subscription_update(obj)
        elif t=='entitlements.active_entitlement_summary.updated': self.entitlement_update(obj)
        elif t=='invoice.payment_failed':
            email=(obj.get('customer_email') or '')
            if email: self.db.queue('payment_failed',{'email':email})
