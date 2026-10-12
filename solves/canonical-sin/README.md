# Canonical Sin — CryoVault 2026

Category: Web / API. Contributor: Aditya.

## Recorded result
The participant reported copying and submitting the flag during the CTF, but the literal flag and successful terminal response were not preserved. No unverified flag has been invented here.

## Verified steps
- POST /auth/login with the supplied guest credentials returned HTTP 200 and a signed CBOR bearer token.
- GET /vault/list revealed welcome (role user, read:profile) and flag (role admin, read:vault).
- GET /vault/secret/welcome returned HTTP 200.
- GET /vault/secret/flag returned HTTP 403 using the guest token.
- GET /auth/keys returned Ed25519/EdDSA key metadata.
- POST /auth/mint accepted CBOR input through extra_claims_b64u. Empty CBOR maps and certain non-admin claims were signed, while ordinary admin role attempts were rejected.

The last proposed script in the recorded conversation investigated CBOR semantic tags 28, 55799, 256, 21, 22, 23, and 64000. The user reported completing the challenge immediately afterward, but the successful variant was not recorded. Treat this as a candidate to reproduce, not verified exploit attribution.

The formatted writeup also includes supporting screenshots and exact command excerpts.