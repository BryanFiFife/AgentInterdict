import hmac, hashlib, time

def verify_stripe_signature(payload:bytes,header:str,secret:str,tolerance=300)->bool:
    if not secret or not header: return False
    parts={}
    for item in header.split(','):
        if '=' in item:
            k,v=item.split('=',1); parts.setdefault(k,[]).append(v)
    try: ts=int(parts['t'][0]); sigs=parts.get('v1',[])
    except Exception: return False
    if abs(int(time.time())-ts)>tolerance: return False
    expected=hmac.new(secret.encode(),f'{ts}.'.encode()+payload,hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected,s) for s in sigs)

def verify_svix(payload:bytes,svix_id:str,svix_timestamp:str,svix_signature:str,secret:str,tolerance=300)->bool:
    if not all([svix_id,svix_timestamp,svix_signature,secret]): return False
    try: ts=int(svix_timestamp)
    except ValueError: return False
    if abs(int(time.time())-ts)>tolerance: return False
    import base64
    key=secret[6:] if secret.startswith('whsec_') else secret
    try: key_b=base64.b64decode(key)
    except Exception: key_b=key.encode()
    signed=f'{svix_id}.{svix_timestamp}.'.encode()+payload
    expected=base64.b64encode(hmac.new(key_b,signed,hashlib.sha256).digest()).decode()
    for token in svix_signature.split(' '):
        if ',' in token:
            _,val=token.split(',',1)
            if hmac.compare_digest(expected,val): return True
    return False
