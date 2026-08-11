import base64,json,time,secrets,hashlib
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def generate_keypair(private_path:Path,public_path:Path):
    private_path=Path(private_path); public_path=Path(public_path); private_path.parent.mkdir(parents=True,exist_ok=True); public_path.parent.mkdir(parents=True,exist_ok=True)
    key=Ed25519PrivateKey.generate()
    private_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    public_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    try: private_path.chmod(0o600)
    except OSError: pass

def new_activation_key(): return 'mgk_'+secrets.token_urlsafe(32)
def activation_hash(k): return hashlib.sha256(k.encode()).hexdigest()

def issue_lease(private_path:Path,customer_id:int,tier:str,installation_id:str,ttl=86400,features=None):
    now=int(time.time()); payload={'iss':'memoryguard','sub':str(customer_id),'tier':tier,'installation_id':installation_id,'iat':now,'exp':now+ttl,'features':sorted(features or [])}
    body=json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
    key=serialization.load_pem_private_key(Path(private_path).read_bytes(),password=None)
    sig=key.sign(body)
    return base64.urlsafe_b64encode(body).decode().rstrip('=')+'.'+base64.urlsafe_b64encode(sig).decode().rstrip('=')
