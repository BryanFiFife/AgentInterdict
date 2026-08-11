"""Production bootstrap helper. Creates signing keys locally; provider objects remain created in Stripe/Resend dashboards or via their APIs."""
from .config import settings
from .licensing import generate_keypair
if __name__=='__main__':
    if not settings.signing_private_key.exists():
        generate_keypair(settings.signing_private_key,settings.signing_public_key)
        print('Generated Ed25519 licence signing keypair.')
    else: print('Signing key already exists; refusing to overwrite.')
