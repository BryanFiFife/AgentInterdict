# MemoryGuard public subscription funnel

**Public funnel:** https://memoryguardai.pages.dev/

The Cloudflare Pages site is the public marketing, lead-capture and subscription
front end. It is separate from the MemoryGuard runtime and commercial control
plane contained in this repository.

## Intended production flow

`memoryguardai.pages.dev`
→ plan selection / lead capture
→ MemoryGuard commercial API
→ Stripe Checkout
→ verified Stripe webhook
→ subscription + active entitlement
→ MemoryGuard activation/licence issuance
→ onboarding
→ installation
→ Stripe Customer Portal for billing changes

## Keep these OUT of Cloudflare Pages

Never expose in browser-side code:

- Stripe secret API keys
- Stripe webhook signing secrets
- Resend API keys or webhook secrets
- licence-signing private keys
- MemoryGuard operator/runtime secrets
- customer activation keys
- customer databases
- production admin credentials

The Pages site may contain public product/plan information and public endpoints
required to initiate the funnel.

The commercial API should explicitly allow the production origin
`https://memoryguardai.pages.dev` only where browser access is required. Do not
use wildcard CORS on privileged licensing/admin routes.

Before launch, verify the whole funnel in Stripe test mode:
landing page → checkout → webhook → entitlement → activation → onboarding →
customer portal → cancellation/downgrade/revocation.
