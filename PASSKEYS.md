# BlindPass accounts, passkeys, and Wallet

BlindPass uses `@simplewebauthn/server` and the locally served
`@simplewebauthn/browser` bundle. Run the server with Node.js 22 or newer and
apply the SQL migrations in `supabase/migrations/` before enabling accounts,
passkeys, or Wallet storage.

## Server environment

Configure these values in the server environment. Keep all secrets server-side;
do not add them to browser code or commit them to source control.

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY` — service-role access is used only by the server.
- `SESSION_SECRET` — at least 32 characters; used to sign the HTTP-only account
  cookie. It is required in production. A temporary random secret is generated
  in development, so development sessions do not survive a server restart.
- `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`
- `MICROSOFT_CLIENT_ID` and `MICROSOFT_CLIENT_SECRET`
- `MICROSOFT_TENANT_ID` — optional; defaults to `common`.
- `APP_ORIGIN` — exact public origin, including scheme and optional port.
- `RP_ID` — hostname only, without scheme, port, or path.

Register `${APP_ORIGIN}/auth/callback` as the redirect URI with each OAuth
provider. The Google sign-in requests the OIDC subject; Microsoft obtains the
account subject from Microsoft Graph. Only a SHA-256 hash of provider plus
subject is stored. Email addresses and raw OAuth subject identifiers are not
stored.

| Environment | `APP_ORIGIN` | `RP_ID` |
| --- | --- | --- |
| Local development | `http://localhost:3000` | `localhost` |
| ngrok example | `https://lyricist-graceless-excuse.ngrok-free.dev` | `lyricist-graceless-excuse.ngrok-free.dev` |
| Render | `https://blindpass.onrender.com` | `blindpass.onrender.com` |

When unset, development uses the localhost origin; Render may use
`RENDER_EXTERNAL_URL` as its origin fallback. Set `APP_ORIGIN` and `RP_ID`
explicitly for ngrok and production. Phone camera verification requires HTTPS.
Passkeys are scoped to their origin and relying-party domain: a passkey
registered on a temporary ngrok hostname will not work on the Render hostname.
To redirect verification results to external partner sites, add each partner's
HTTPS origin to `ALLOWED_RETURN_ORIGINS` as a comma-separated list. Return URLs
outside the configured allowlist are rejected; when no allowed return URL or
referrer is available, cancellation uses the browser's back navigation.

## Passkeys and Wallet privacy

Passkey registration requires an authenticated account and requests user
verification plus a discoverable credential. Passkey private keys stay in the
authenticator; BlindPass stores only credential IDs, public keys, counters, and
transport metadata. The account cookie is HTTP-only, signed, and expires after
30 days.

The MRZ is scanned and validated in the browser. BlindPass stores the Wallet
badge's verified/adult status, document type, issuing country, verification
time, and document expiration time. It does not store document images, raw
MRZ, names, document numbers, or exact dates of birth. A Wallet age-gate
approval requires a fresh user-verified passkey assertion, a current adult
credential, and an unused, unexpired QR session. Verification logs store a
hash of the session token rather than the token itself.

The `users`, `passkeys`, `wallet_credentials`, and verification-log writes are
restricted to the server's Supabase `service_role`; browser roles do not have
direct write access.
