# BlindPass

BlindPass is a privacy-preserving age-verification web app. ID images and MRZ
text are processed in the browser; the server stores only a non-PII age badge,
account/passkey data, and hashed one-time verification identifiers.

## Live deployment

The app is deployed at [https://blindpass.onrender.com](https://blindpass.onrender.com).
The free Render service may spin down while idle, so the first request after a
quiet period can take a little longer while the service cold-starts.

## Local setup

Use Node.js 22 or newer and npm.

```powershell
npm install
Copy-Item .env.example .env
npm start
```

Set `APP_ORIGIN=http://localhost:3000` and `RP_ID=localhost` for local
development. Apply the SQL files in `supabase/migrations/` to the Supabase
project before using accounts, passkeys, or Wallet storage. Keep the Supabase
service-role key and all OAuth client secrets server-side; never put them in
browser code. Replace the sample `SESSION_SECRET` with a random value of at
least 32 characters.

### Environment variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `APP_ORIGIN` | Production | Public HTTPS origin; local development defaults to `http://localhost:3000`. |
| `RP_ID` | Production | WebAuthn relying-party hostname, without scheme or path. |
| `SESSION_SECRET` | Yes | At least 32 characters; signs account and verifier tokens. |
| `OAUTH_SUBJECT_PEPPER` | No | Dedicated HMAC key (at least 32 characters) for OAuth subject pseudonymisation; defaults to `SESSION_SECRET`. |
| `SUPABASE_URL` | With account storage | Supabase project URL. |
| `SUPABASE_SERVICE_ROLE_KEY` | With account storage | Server-only Supabase service-role key. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Optional | Enable Google sign-in. |
| `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET` | Optional | Enable Microsoft sign-in. |
| `MICROSOFT_TENANT_ID` | No | Microsoft tenant; defaults to `common`. |
| `ALLOWED_RETURN_ORIGINS` | No | Comma-separated HTTPS partner origins allowed as verifier return destinations. |
| `PORT` | No | HTTP port; defaults to `3000` and is set by Render. |

Register `${APP_ORIGIN}/auth/callback` with each enabled OAuth provider. OAuth
callbacks are bound to an HTTP-only state cookie and use PKCE.
Existing OAuth accounts created with the earlier unkeyed hash are upgraded to
the keyed HMAC when their owner next signs in.

## Tests

```powershell
npm test
npm run check
```

## MIDV-2020 benchmark

Extract MIDV-2020 images locally, then point the script at the extracted image
directory. It recursively processes common image formats, reports anonymized
per-image latency and aggregate MRZ/parse/check-digit rates, and emits only
likely OCR confusion counts—not image filenames, OCR text, or extracted PII.

```powershell
node scripts/benchmark-midv2020.js 'E:\dataset'
```

Alternatively, set `MIDV2020_DIR` to the extracted dataset directory. If the
repository-root `eng.traineddata` file is present, the benchmark uses it;
otherwise Tesseract.js downloads its English language model. The browser
bundle, worker, and WASM core are served locally from `node_modules`.

## Privacy and security

The browser performs MRZ checks and OCR locally. The server requires a fresh,
user-verified passkey assertion before saving a Wallet credential. Verifier
results are HMAC-signed, short-lived, state-bound, and single-use. The
`verifications` table has RLS enabled and grants access only to the server's
Supabase `service_role`.
