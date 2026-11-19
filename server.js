import express from 'express';

const app = express();
const PORT = 3000;
const ORIGIN = `http://localhost:${PORT}`;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID || '';
const MICROSOFT_CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET || '';
const MICROSOFT_TENANT_ID = process.env.MICROSOFT_TENANT_ID || 'common';

const sessions = new Map();

function createSession(verifier = 'Discord', returnTo = `${ORIGIN}/verifier.html`) {
    const sessionId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    const session = {
        sessionId,
        verifier,
        returnTo,
        loggedIn: false,
        provider: null,
        email: null,
    };
    sessions.set(sessionId, session);
    return session;
}

function safeReturnUrl(rawUrl) {
    const fallback = `${ORIGIN}/verifier.html`;
    if (!rawUrl) return fallback;
    try {
        const parsed = new URL(String(rawUrl), ORIGIN);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            return fallback;
        }
        if (parsed.origin !== ORIGIN) {
            return fallback;
        }
        if (parsed.pathname === '/start' || parsed.pathname.startsWith('/auth/')) {
            return fallback;
        }
        return parsed.toString();
    } catch {
        return fallback;
    }
}

function decodeJwtPayload(token) {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
}

async function exchangeGoogleCode(code, redirectUri) {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            code,
            client_id: GOOGLE_CLIENT_ID,
            client_secret: GOOGLE_CLIENT_SECRET,
            redirect_uri: redirectUri,
            grant_type: 'authorization_code',
        }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok) {
        throw new Error(tokenData.error_description || tokenData.error || 'Google token exchange failed');
    }

    const idClaims = decodeJwtPayload(tokenData.id_token);
    if (idClaims?.email) {
        return idClaims.email;
    }

    const userRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const userData = await userRes.json();
    if (!userData.email) {
        throw new Error('Google userinfo did not return an email');
    }
    return userData.email;
}

async function exchangeMicrosoftCode(code, redirectUri) {
    const tokenUrl = `https://login.microsoftonline.com/${MICROSOFT_TENANT_ID}/oauth2/v2.0/token`;
    const tokenRes = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            code,
            client_id: MICROSOFT_CLIENT_ID,
            client_secret: MICROSOFT_CLIENT_SECRET,
            redirect_uri: redirectUri,
            grant_type: 'authorization_code',
        }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok) {
        throw new Error(tokenData.error_description || tokenData.error || 'Microsoft token exchange failed');
    }

    const idClaims = decodeJwtPayload(tokenData.id_token);
    const claimEmail = idClaims?.email || idClaims?.preferred_username;
    if (claimEmail) {
        return claimEmail;
    }

    const graphRes = await fetch('https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const graphData = await graphRes.json();
    const graphEmail = graphData.mail || graphData.userPrincipalName;
    if (!graphEmail) {
        throw new Error('Microsoft Graph did not return an email');
    }
    return graphEmail;
}

app.get('/', (req, res, next) => {
    if (!req.query.session) {
        const session = createSession('Discord', `${ORIGIN}/verifier.html`);
        return res.redirect(302, `/?session=${encodeURIComponent(session.sessionId)}`);
    }
    next();
});

app.use(express.static('public'));

app.get('/start', (req, res) => {
    const verifier = String(req.query.verifier || 'Discord');
    const returnTo = safeReturnUrl(req.query.return_to);
    const session = createSession(verifier, returnTo);
    res.redirect(302, `/?session=${encodeURIComponent(session.sessionId)}`);
});

app.get('/api/session/:sessionId', (req, res) => {
    const session = sessions.get(req.params.sessionId);
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    res.json(session);
});

app.get('/auth/callback', async (req, res) => {
    try {
        if (req.query.error) {
            return res.status(400).send(`OAuth error: ${String(req.query.error_description || req.query.error)}`);
        }

        const parsed = JSON.parse(Buffer.from(String(req.query.state || ''), 'base64url').toString('utf8'));
        const provider = parsed.provider === 'microsoft' ? 'microsoft' : 'google';

        let session = sessions.get(parsed.sessionId);
        if (!session) {
            session = createSession('Discord', `${ORIGIN}/verifier.html`);
            sessions.set(parsed.sessionId, session);
            session.sessionId = parsed.sessionId;
        }

        const redirectUri = `${ORIGIN}/auth/callback`;
        let email;

        if (req.query.code) {
            const code = String(req.query.code);
            if (provider === 'google') {
                if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
                    return res.status(500).send('Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET');
                }
                email = await exchangeGoogleCode(code, redirectUri);
            } else {
                if (!MICROSOFT_CLIENT_ID || !MICROSOFT_CLIENT_SECRET) {
                    return res.status(500).send('Missing MICROSOFT_CLIENT_ID or MICROSOFT_CLIENT_SECRET');
                }
                email = await exchangeMicrosoftCode(code, redirectUri);
            }
        } else {
            email = String(req.query.demo_email || `demo@${provider}.local`);
        }

        session.loggedIn = true;
        session.provider = provider;
        session.email = email;

        const nextUrl = `/?session=${encodeURIComponent(session.sessionId)}`;
        res.status(200).send(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Signing in...</title></head>
<body>
  <p>Signed in via ${session.provider}. Continuing...</p>
  <a href="${nextUrl}">Continue to BlindPass</a>
  <script>window.location.replace(${JSON.stringify(nextUrl)});</script>
</body>
</html>`);
    } catch (err) {
        res.status(400).send(`Authentication failed: ${err instanceof Error ? err.message : 'Invalid callback'}`);
    }
});

app.get('/auth/:provider', (req, res) => {
    const provider = req.params.provider === 'microsoft' ? 'microsoft' : 'google';
    const rawSessionId = String(req.query.session || '');

    let session = sessions.get(rawSessionId);
    if (!session) {
        session = createSession('Discord', `${ORIGIN}/verifier.html`);
    }

    const state = Buffer.from(JSON.stringify({ sessionId: session.sessionId, provider })).toString('base64url');
    const redirectUri = `${ORIGIN}/auth/callback`;

    if (provider === 'google' && GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
        const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        url.searchParams.set('client_id', GOOGLE_CLIENT_ID);
        url.searchParams.set('redirect_uri', redirectUri);
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('scope', 'openid email profile');
        url.searchParams.set('state', state);
        return res.redirect(302, url.toString());
    }

    if (provider === 'microsoft' && MICROSOFT_CLIENT_ID && MICROSOFT_CLIENT_SECRET) {
        const url = new URL(`https://login.microsoftonline.com/${MICROSOFT_TENANT_ID}/oauth2/v2.0/authorize`);
        url.searchParams.set('client_id', MICROSOFT_CLIENT_ID);
        url.searchParams.set('redirect_uri', redirectUri);
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('scope', 'openid email profile User.Read');
        url.searchParams.set('response_mode', 'query');
        url.searchParams.set('state', state);
        return res.redirect(302, url.toString());
    }

    res.redirect(302, `/auth/callback?state=${encodeURIComponent(state)}&demo_email=demo@${provider}.local`);
});

app.use((req, res) => {
    res.status(404).send('Not found');
});

app.listen(PORT, () => {
    console.log(`BlindPass running on ${ORIGIN}`);
    console.log(`Verifier start page: ${ORIGIN}/verifier.html`);
});