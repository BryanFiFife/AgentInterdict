import requests

class StripeProvider:
    def __init__(self,key): self.key=key
    def _headers(self): return {'Authorization':f'Bearer {self.key}'}
    def checkout(self,price_id,success_url,cancel_url,email=None):
        data=[('mode','subscription'),('line_items[0][price]',price_id),('line_items[0][quantity]','1'),('success_url',success_url),('cancel_url',cancel_url)]
        if email: data.append(('customer_email',email))
        r=requests.post('https://api.stripe.com/v1/checkout/sessions',headers=self._headers(),data=data,timeout=15); r.raise_for_status(); return r.json()
    def portal(self,customer_id,return_url):
        r=requests.post('https://api.stripe.com/v1/billing_portal/sessions',headers=self._headers(),data={'customer':customer_id,'return_url':return_url},timeout=15); r.raise_for_status(); return r.json()

class ResendProvider:
    def __init__(self,key,from_addr): self.key=key; self.from_addr=from_addr
    def send(self,to,subject,html):
        r=requests.post('https://api.resend.com/emails',headers={'Authorization':f'Bearer {self.key}','Content-Type':'application/json'},json={'from':self.from_addr,'to':[to],'subject':subject,'html':html},timeout=15); r.raise_for_status(); return r.json()
