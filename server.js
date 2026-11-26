import express from 'express';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import QRCode from 'qrcode';
import { createClient } from '@supabase/supabase-js';
import {
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { ICAO_COUNTRIES } from './public/icao-countries.js';
import {
    resolvePasskeyCredential,
    resolveOAuthUser,
} from './server/accounts.js';
import {
    clearUserSessionCookie,
    readUserSessionCookie,
    serializeUserSessionCookie,
} from './server/auth.js';
import {
    clearExpiredPasskeyChallenges,
    consumePasskeyChallenge,
    isValidAuthenticationResponse,
    isValidUserId,
    issuePasskeyChallenge,
} from './server/passkeys.js';
import {
    claimVerificationToken,
    cancelVerificationSession,
    createVerificationRecord,
    resolveVerifierLaunch,
} from './server/verification.js';
import {
    createWalletCredentialRecord,
    formatWalletCredential,
    validateWalletSavePayload,
    validateWalletApproval,
} from './server/wallet.js';
import { resolveWebAuthnConfig } from './server/webauthn-config.js';
import {
    createVerifierReturnToken,
    verifyVerifierReturnToken,
} from './server/verifier-token.js';

const app = express();
const ROOT_DIR = fileURLToPath(new URL('.', import.meta.url));
const PORT = Number(process.env.PORT) || 3000;
const { configuredOrigin, expectedOrigin: ORIGIN, rpID } = resolveWebAuthnConfig({
    port: PORT,
    appOrigin: process.env.APP_ORIGIN,
    renderExternalUrl: process.env.RENDER_EXTERNAL_URL,
    rpID: process.env.RP_ID,
    nodeEnv: process.env.NODE_ENV,
});
const SESSION_LIFETIME_MS = 20 * 60 * 1000;
const OAUTH_STATE_LIFETIME_MS = 10 * 60 * 1000;
const MAX_ACTIVE_SESSIONS = 10_000;
const MAX_OAUTH_STATES = 1_000;
const MAX_VERIFIER_RETURN_NONCES = 10_000;
const PASSKEY_CHALLENGES = new Map();
const OAUTH_STATES = new Map();
const VERIFIER_RETURN_NONCES = new Map();
const allowedReturnOrigins = new Set([ORIGIN]);

for (const value of (process.env.ALLOWED_RETURN_ORIGINS || '').split(',')) {
    const origin = value.trim();
    if (!origin) continue;
    const parsedOrigin = new URL(origin);
    const isLocalHttp =
        parsedOrigin.protocol === 'http:' &&
        ['localhost', '127.0.0.1', '[::1]'].includes(parsedOrigin.hostname);
    if (
        (parsedOrigin.protocol !== 'https:' && !isLocalHttp) ||
        parsedOrigin.pathname !== '/' ||
        parsedOrigin.search ||
        parsedOrigin.hash ||
        parsedOrigin.username ||
        parsedOrigin.password
    ) {
        throw new Error('ALLOWED_RETURN_ORIGINS must contain HTTPS origins (HTTP is allowed only for localhost development)');
    }
    allowedReturnOrigins.add(parsedOrigin.origin);
}

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID || '';
const MICROSOFT_CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET || '';
const MICROSOFT_TENANT_ID = process.env.MICROSOFT_TENANT_ID || 'common';
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://cersffyrlkbcodpaavwc.supabase.co';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const SESSION_SECRET = process.env.SESSION_SECRET ||
    (process.env.NODE_ENV === 'production' ? '' : randomBytes(32).toString('base64url'));
const ISSUING_COUNTRY_CODES = new Set(ICAO_COUNTRIES.map(([, code]) => code));
if (!SESSION_SECRET) {
    throw new Error('SESSION_SECRET must be configured in production');
}
if (SESSION_SECRET.length < 32) {
    throw new Error('SESSION_SECRET must be at least 32 characters');
}
const OAUTH_SUBJECT_PEPPER = process.env.OAUTH_SUBJECT_PEPPER || SESSION_SECRET;
if (OAUTH_SUBJECT_PEPPER.length < 32) {
    throw new Error('OAUTH_SUBJECT_PEPPER must be at least 32 characters');
}

const sessions = new Map();
let supabaseAdmin = null;
app.use((req, res, next) => {
    res.set({
        'Content-Security-Policy': [
            "default-src 'self'",
            "base-uri 'self'",
            "object-src 'none'",
            "frame-ancestors 'none'",
            "form-action 'self' https://accounts.google.com https://login.microsoftonline.com",
            "script-src 'self' 'wasm-unsafe-eval'",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com data:",
            "img-src 'self' data: blob:",
            "media-src 'self' blob:",
            "worker-src 'self' blob:",
            "connect-src 'self' https://cdn.jsdelivr.net",
        ].join('; '),
        'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Permissions-Policy': 'camera=(self), publickey-credentials-get=(self), publickey-credentials-create=(self)',
    });
    if (req.path === '/verifier.html') res.set('Cache-Control', 'no-store');
    next();
});
app.use(express.json({ limit: '64kb' }));

const sessionCleanup = setInterval(() => {
    const now = Date.now();
    for (const [sessionId, session] of sessions) {
        if (session.expiresAt <= now) sessions.delete(sessionId);
    }
    clearExpiredPasskeyChallenges(PASSKEY_CHALLENGES, now);
    for (const [state, record] of OAUTH_STATES) {
        if (record.expiresAt <= now) OAUTH_STATES.delete(state);
    }
    for (const [nonce, record] of VERIFIER_RETURN_NONCES) {
        if (record.expiresAt <= now) VERIFIER_RETURN_NONCES.delete(nonce);
    }
}, 60_000);
sessionCleanup.unref();

function getSession(sessionId) {
    const session = sessions.get(sessionId);
    if (!session) return null;
    if (session.expiresAt <= Date.now()) {
        sessions.delete(sessionId);
        return null;
    }
    return session;
}

function createSession(verifier = 'Verifier', returnTo = null, verifierState) {
    const now = Date.now();
    for (const [sessionId, session] of sessions) {
        if (session.expiresAt <= now) sessions.delete(sessionId);
    }
    if (sessions.size >= MAX_ACTIVE_SESSIONS) {
        throw new Error('Too many active verification sessions');
    }
    const sessionId = randomBytes(32).toString('base64url');
    const session = {
        sessionId,
        verifier,
        returnTo,
        verifierState,
        loggedIn: false,
        provider: null,
        userId: null,
        verified: false,
        isOver18: null,
        documentType: null,
        issuingCountry: null,
        isAdult: null,
        cancelled: false,
        verificationTokenUsed: false,
        verificationPending: false,
        returnTokenIssued: false,
        returnToken: null,
        returnTokenNonce: null,
        expiresAt: now + SESSION_LIFETIME_MS,
    };
    sessions.set(sessionId, session);
    return session;
}

function getSupabaseAdmin() {
    if (!SUPABASE_SERVICE_ROLE_KEY) return null;
    if (!supabaseAdmin) {
        supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
            auth: {
                autoRefreshToken: false,
                persistSession: false,
            },
        });
    }
    return supabaseAdmin;
}

function hasExactFields(value, requiredFields, optionalFields = []) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const keys = Object.keys(value);
    return requiredFields.every((field) => Object.hasOwn(value, field)) &&
        keys.every((key) => requiredFields.includes(key) || optionalFields.includes(key));
}

function getAuthenticatedUserId(req) {
    return readUserSessionCookie(req.get('cookie'), SESSION_SECRET);
}

function setAuthenticatedUserCookie(res, userId) {
    res.append(
        'Set-Cookie',
        serializeUserSessionCookie(
            userId,
            SESSION_SECRET,
            configuredOrigin.protocol === 'https:'
        )
    );
}

function clearAuthenticatedUserCookie(res) {
    res.append(
        'Set-Cookie',
        clearUserSessionCookie(configuredOrigin.protocol === 'https:')
    );
}

function getUserContext(req, res, body) {
    const cookieUserId = getAuthenticatedUserId(req);
    if (body.qrToken !== undefined) {
        if (typeof body.qrToken !== 'string') {
            res.status(400).json({ error: 'Invalid QR session token' });
            return null;
        }
        const session = getSession(body.qrToken);
        if (!session) {
            res.status(404).json({ error: 'Session not found or expired' });
            return null;
        }
        if (!session.loggedIn || !isValidUserId(session.userId)) {
            res.status(403).json({ error: 'Sign in on the requesting device before continuing' });
            return null;
        }
        if (session.cancelled) {
            res.status(410).json({ error: 'This verification session was cancelled' });
            return null;
        }
        if (
            session.verified ||
            session.verificationTokenUsed ||
            session.verificationPending
        ) {
            res.status(409).json({ error: 'This verification session is already complete or in progress' });
            return null;
        }
        if (cookieUserId && cookieUserId !== session.userId) {
            res.status(403).json({ error: 'This QR session belongs to another account' });
            return null;
        }
        return {
            userId: session.userId,
            sessionId: session.sessionId,
            session,
        };
    }

    if (!cookieUserId) {
        res.status(401).json({ error: 'Sign in to your BlindPass account first' });
        return null;
    }
    return { userId: cookieUserId, sessionId: null, session: null };
}

async function loadWalletCredential(supabase, userId) {
    const { data, error } = await supabase
        .from('wallet_credentials')
        .select('verified, is_adult, document_type, issuing_country, verified_at, expires_at')
        .eq('user_id', userId)
        .maybeSingle();
    if (error) throw error;
    return data;
}

async function loadAccountSnapshot(supabase, userId) {
    const [userResult, passkeyResult, wallet] = await Promise.all([
        supabase
            .from('users')
            .select('oauth_provider')
            .eq('id', userId)
            .maybeSingle(),
        supabase
            .from('passkeys')
            .select('id', { count: 'exact', head: true })
            .eq('user_id', userId),
        loadWalletCredential(supabase, userId),
    ]);

    if (userResult.error) throw userResult.error;
    if (passkeyResult.error) throw passkeyResult.error;
    if (!userResult.data) throw new Error('BlindPass account was not found');
    return {
        provider: userResult.data.oauth_provider,
        accountLabel: `${userId.slice(0, 8)}…${userId.slice(-4)}`,
        hasPasskey: (passkeyResult.count || 0) > 0,
        wallet: formatWalletCredential(wallet),
    };
}

function rejectUnexpectedOrigin(req, res, action) {
    const requestOrigin = req.get('origin');
    if (requestOrigin !== ORIGIN) {
        res.status(403).json({ error: `${action} must come from the configured app origin` });
        return true;
    }
    return false;
}

function isSafeEqual(left, right) {
    if (typeof left !== 'string' || typeof right !== 'string') return false;
    const leftBuffer = Buffer.from(left);
    const rightBuffer = Buffer.from(right);
    return leftBuffer.length === rightBuffer.length &&
        timingSafeEqual(leftBuffer, rightBuffer);
}

function getCookieValue(cookieHeader, name) {
    if (typeof cookieHeader !== 'string') return '';
    const cookie = cookieHeader.split(';')
        .map((part) => part.trim())
        .find((part) => part.startsWith(`${name}=`));
    return cookie ? cookie.slice(name.length + 1) : '';
}

function serializeOAuthStateCookie(state, secure) {
    return `blindpass_oauth_state=${state}; Path=/auth/callback; Max-Age=${OAUTH_STATE_LIFETIME_MS / 1000}; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`;
}

function clearOAuthStateCookie(secure) {
    return `blindpass_oauth_state=; Path=/auth/callback; Max-Age=0; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`;
}

async function exchangeGoogleCode(code, redirectUri, codeVerifier) {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            code,
            client_id: GOOGLE_CLIENT_ID,
            client_secret: GOOGLE_CLIENT_SECRET,
            redirect_uri: redirectUri,
            grant_type: 'authorization_code',
            code_verifier: codeVerifier,
        }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok) {
        throw new Error(tokenData.error_description || tokenData.error || 'Google token exchange failed');
    }

    const userRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const userData = await userRes.json();
    if (!userRes.ok || typeof userData.sub !== 'string' || !userData.sub) {
        throw new Error('Google userinfo did not return an account subject');
    }
    return userData.sub;
}

async function exchangeMicrosoftCode(code, redirectUri, codeVerifier) {
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
            code_verifier: codeVerifier,
        }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok) {
        throw new Error(tokenData.error_description || tokenData.error || 'Microsoft token exchange failed');
    }

    const graphRes = await fetch('https://graph.microsoft.com/v1.0/me?$select=id', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const graphData = await graphRes.json();
    if (!graphRes.ok || typeof graphData.id !== 'string' || !graphData.id) {
        throw new Error('Microsoft Graph did not return an account subject');
    }
    return graphData.id;
}

app.use(
    '/vendor/simplewebauthn',
    express.static(resolve(ROOT_DIR, 'node_modules/@simplewebauthn/browser/dist/bundle'), {
        maxAge: '1h',
    })
);
app.use(
    '/vendor/tesseract',
    express.static(resolve(ROOT_DIR, 'node_modules/tesseract.js/dist'), {
        maxAge: '1h',
    })
);
app.use(
    '/vendor/tesseract-core',
    express.static(resolve(ROOT_DIR, 'node_modules/tesseract.js-core'), {
        maxAge: '1h',
        index: false,
    })
);
app.use(express.static(resolve(ROOT_DIR, 'public')));

app.post('/api/verifier/verify-token', (req, res) => {
    if (rejectUnexpectedOrigin(req, res, 'Verifier result')) return;
    if (!hasExactFields(req.body, ['token', 'state'])) {
        return res.status(400).json({ error: 'Invalid verifier result' });
    }

    const payload = verifyVerifierReturnToken(req.body.token, {
        secret: SESSION_SECRET,
        expectedState: req.body.state,
        pendingNonces: VERIFIER_RETURN_NONCES,
    });
    if (!payload) {
        return res.status(401).json({ error: 'Verifier result is invalid, expired, or already used' });
    }

    res.set('Cache-Control', 'no-store');
    return res.json({
        verified: true,
        isAdult: payload.is_adult,
    });
});

app.get('/api/account', async (req, res) => {
    const userId = getAuthenticatedUserId(req);
    if (!userId) return res.status(401).json({ error: 'Sign in to your BlindPass account first' });
    const supabase = getSupabaseAdmin();
    if (!supabase) {
        return res.status(503).json({ error: 'BlindPass account storage is not configured' });
    }

    try {
        const account = await loadAccountSnapshot(supabase, userId);
        res.set('Cache-Control', 'no-store');
        return res.json({ loggedIn: true, ...account });
    } catch (error) {
        console.error(
            'Could not load the BlindPass account:',
            error instanceof Error ? error.message : 'database error'
        );
        return res.status(502).json({ error: 'Could not load the BlindPass account' });
    }
});

app.get('/api/wallet', async (req, res) => {
    const userId = getAuthenticatedUserId(req);
    if (!userId) return res.status(401).json({ error: 'Sign in to view your BlindPass Wallet' });
    const supabase = getSupabaseAdmin();
    if (!supabase) {
        return res.status(503).json({ error: 'BlindPass Wallet storage is not configured' });
    }

    try {
        const wallet = await loadWalletCredential(supabase, userId);
        res.set('Cache-Control', 'no-store');
        return res.json({ wallet: formatWalletCredential(wallet) });
    } catch (error) {
        console.error(
            'Could not load the BlindPass Wallet:',
            error instanceof Error ? error.message : 'database error'
        );
        return res.status(502).json({ error: 'Could not load the BlindPass Wallet' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    if (rejectUnexpectedOrigin(req, res, 'Sign out')) return;
    clearAuthenticatedUserCookie(res);
    return res.json({ loggedOut: true });
});

app.post('/api/wallet/save/options', async (req, res) => {
    if (rejectUnexpectedOrigin(req, res, 'Wallet update')) return;
    if (!hasExactFields(req.body, [], ['qrToken'])) {
        return res.status(400).json({ error: 'Invalid Wallet credential request' });
    }
    const context = getUserContext(req, res, req.body);
    if (!context) return;
    const supabase = getSupabaseAdmin();
    if (!supabase) {
        return res.status(503).json({ error: 'Passkey storage is not configured on the server' });
    }

    try {
        const { data: credentials, error } = await supabase
            .from('passkeys')
            .select('credential_id, transports')
            .eq('user_id', context.userId);
        if (error) throw error;
        if (!credentials?.length) {
            return res.status(404).json({
                code: 'passkey-not-found',
                error: 'Register a passkey before saving a Wallet credential',
            });
        }

        const options = await generateAuthenticationOptions({
            rpID,
            timeout: 60_000,
            userVerification: 'required',
            allowCredentials: credentials.map((credential) => ({
                id: credential.credential_id,
                transports: Array.isArray(credential.transports)
                    ? credential.transports
                    : undefined,
            })),
        });
        const flowToken = issuePasskeyChallenge(PASSKEY_CHALLENGES, {
            challenge: options.challenge,
            ceremony: 'wallet-save',
            userId: context.userId,
            sessionId: context.sessionId,
            sessionExpiresAt: context.session?.expiresAt,
        });
        res.set('Cache-Control', 'no-store');
        return res.json({ flowToken, options });
    } catch (error) {
        console.error(
            'Could not create Wallet save passkey options:',
            error instanceof Error ? error.message : 'database error'
        );
        return res.status(502).json({ error: 'Could not start Wallet credential confirmation' });
    }
});

app.post('/api/wallet/save', async (req, res) => {
    if (rejectUnexpectedOrigin(req, res, 'Wallet update')) return;
    if (!hasExactFields(
        req.body,
        [
            'verified',
            'isAdult',
            'documentType',
            'issuingCountry',
            'expiresAt',
            'flowToken',
            'assertion',
        ],
        ['qrToken']
    )) {
        return res.status(400).json({ error: 'Invalid Wallet credential payload' });
    }
    if (
        typeof req.body.flowToken !== 'string' ||
        !isValidAuthenticationResponse(req.body.assertion)
    ) {
        return res.status(400).json({ error: 'Wallet credentials require a passkey assertion' });
    }
    const walletPayload = {
        ...(req.body.qrToken === undefined ? {} : { qrToken: req.body.qrToken }),
        verified: req.body.verified,
        isAdult: req.body.isAdult,
        documentType: req.body.documentType,
        issuingCountry: req.body.issuingCountry,
        expiresAt: req.body.expiresAt,
    };
    const validation = validateWalletSavePayload(walletPayload, ISSUING_COUNTRY_CODES);
    if (!validation.ok) {
        return res.status(400).json({ error: 'The locally verified ID outcome is invalid or expired' });
    }
    const context = getUserContext(req, res, req.body);
    if (!context) return;
    const supabase = getSupabaseAdmin();
    if (!supabase) {
        return res.status(503).json({ error: 'BlindPass Wallet storage is not configured' });
    }

    try {
        const challenge = consumePasskeyChallenge(
            PASSKEY_CHALLENGES,
            req.body.flowToken,
            {
                ceremony: 'wallet-save',
                userId: context.userId,
                sessionId: context.sessionId,
            }
        );
        if (!challenge) {
            return res.status(409).json({
                error: 'Wallet save passkey challenge is missing, expired, or already used',
            });
        }
        const { data: passkey, error: passkeyError } = await supabase
            .from('passkeys')
            .select('id, user_id, credential_id, public_key, counter, transports')
            .eq('user_id', context.userId)
            .eq('credential_id', req.body.assertion.id)
            .maybeSingle();
        if (passkeyError) throw passkeyError;
        if (!passkey || !Number.isSafeInteger(Number(passkey.counter))) {
            return res.status(401).json({ error: 'This account passkey was not recognized' });
        }

        let authentication;
        try {
            authentication = await verifyAuthenticationResponse({
                response: req.body.assertion,
                expectedChallenge: challenge.challenge,
                expectedOrigin: ORIGIN,
                expectedRPID: rpID,
                credential: {
                    id: passkey.credential_id,
                    publicKey: Buffer.from(passkey.public_key, 'base64url'),
                    counter: Number(passkey.counter),
                    transports: Array.isArray(passkey.transports)
                        ? passkey.transports
                        : undefined,
                },
                requireUserVerification: true,
            });
        } catch {
            return res.status(401).json({ error: 'Wallet save passkey assertion could not be verified' });
        }
        if (
            !authentication.verified ||
            !authentication.authenticationInfo.userVerified ||
            authentication.authenticationInfo.credentialID !== passkey.credential_id
        ) {
            return res.status(401).json({ error: 'Wallet save passkey assertion could not be verified' });
        }
        const { data: updatedCredential, error: counterError } = await supabase
            .from('passkeys')
            .update({ counter: authentication.authenticationInfo.newCounter })
            .eq('id', passkey.id)
            .eq('counter', Number(passkey.counter))
            .select('id')
            .maybeSingle();
        if (counterError) throw counterError;
        if (!updatedCredential) {
            return res.status(409).json({ error: 'This passkey was used concurrently. Try again.' });
        }

        const { data, error } = await supabase
            .from('wallet_credentials')
            .upsert(
                createWalletCredentialRecord(
                    context.userId,
                    validation.credential,
                    new Date().toISOString()
                ),
                { onConflict: 'user_id' }
            )
            .select('verified, is_adult, document_type, issuing_country, verified_at, expires_at')
            .single();
        if (error) {
            console.error('Could not save the BlindPass Wallet credential:', error.code || 'database error');
            return res.status(502).json({ error: 'Could not save the BlindPass Wallet credential' });
        }
        res.set('Cache-Control', 'no-store');
        return res.status(201).json({ wallet: formatWalletCredential(data) });
    } catch (error) {
        console.error(
            'Could not save the BlindPass Wallet credential:',
            error instanceof Error ? error.message : 'database error'
        );
        return res.status(502).json({ error: 'Could not save the BlindPass Wallet credential' });
    }
});

app.get('/start', (req, res) => {
    const { verifier, returnTo } = resolveVerifierLaunch(
        req.query,
        req.get('referer'),
        ORIGIN,
        allowedReturnOrigins
    );
    const requestedState = req.query.state;
    if (
        requestedState !== undefined &&
        (typeof requestedState !== 'string' ||
            !/^[A-Za-z0-9_-]{16,128}$/.test(requestedState))
    ) {
        return res.status(400).send('Invalid verifier state.');
    }
    let session;
    try {
        session = createSession(
            verifier,
            returnTo,
            requestedState || randomBytes(24).toString('base64url')
        );
    } catch (error) {
        console.error(
            'Could not create verification session:',
            error instanceof Error ? error.message : 'unknown error'
        );
        return res.status(503).send('Too many active verification sessions. Try again shortly.');
    }
    res.set('Cache-Control', 'no-store');
    res.redirect(302, `/?session=${encodeURIComponent(session.sessionId)}`);
});

app.get('/api/session/:sessionId', async (req, res) => {
    const session = getSession(req.params.sessionId);
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }

    const cookieUserId = getAuthenticatedUserId(req);
    if (session.userId && cookieUserId && session.userId !== cookieUserId) {
        return res.status(403).json({ error: 'This verification session belongs to another account' });
    }

    let account = null;
    if (session.userId && cookieUserId === session.userId) {
        const supabase = getSupabaseAdmin();
        if (!supabase) {
            return res.status(503).json({ error: 'BlindPass account storage is not configured' });
        }
        try {
            account = await loadAccountSnapshot(supabase, session.userId);
            session.provider = account.provider;
        } catch (error) {
            console.error(
                'Could not load QR session account details:',
                error instanceof Error ? error.message : 'database error'
            );
            return res.status(502).json({ error: 'Could not load QR session account details' });
        }
    }

    res.set('Cache-Control', 'no-store');
    return res.json({
        sessionId: session.sessionId,
        verifier: session.verifier,
        verifierName: session.verifier,
        returnTo: session.returnTo,
        loggedIn: session.loggedIn,
        provider: session.provider,
        verified: session.verified,
        isOver18: session.isOver18,
        hasPasskey: account?.hasPasskey || false,
        accountLabel: account?.accountLabel || null,
        wallet: account?.wallet || null,
        cancelled: session.cancelled,
        expiresAt: session.expiresAt,
        appOrigin: ORIGIN,
        phoneReady: configuredOrigin.protocol === 'https:',
    });
});

app.post('/api/session/:sessionId/claim', (req, res) => {
    if (rejectUnexpectedOrigin(req, res, 'Session claim')) return;
    if (!hasExactFields(req.body, [])) {
        return res.status(400).json({ error: 'Invalid session claim request' });
    }
    const session = getSession(req.params.sessionId);
    if (!session) {
        return res.status(404).json({ error: 'Session not found or expired' });
    }
    const userId = getAuthenticatedUserId(req);
    if (!userId) return res.status(401).json({ error: 'Sign in before claiming this session' });
    if (session.cancelled || session.verified) {
        return res.status(409).json({ error: 'This verification session is no longer available' });
    }
    if (session.userId && session.userId !== userId) {
        return res.status(403).json({ error: 'This verification session belongs to another account' });
    }

    session.userId = userId;
    session.loggedIn = true;
    res.set('Cache-Control', 'no-store');
    return res.json({ claimed: true });
});

app.post('/api/session/:sessionId/return-token', (req, res) => {
    if (rejectUnexpectedOrigin(req, res, 'Verifier result')) return;
    if (!hasExactFields(req.body, [])) {
        return res.status(400).json({ error: 'Invalid verifier result request' });
    }
    const session = getSession(req.params.sessionId);
    if (!session) {
        return res.status(404).json({ error: 'Session not found or expired' });
    }
    if (!session.verified || session.cancelled) {
        return res.status(409).json({ error: 'This verification session has no completed result' });
    }
    if (session.returnTokenIssued) {
        const pending = VERIFIER_RETURN_NONCES.get(session.returnTokenNonce);
        if (pending && pending.expiresAt > Date.now()) {
            res.set('Cache-Control', 'no-store');
            return res.json({
                token: session.returnToken,
                state: session.verifierState,
            });
        }
        return res.status(409).json({ error: 'The verifier result has expired or already been used' });
    }
    for (const [nonce, record] of VERIFIER_RETURN_NONCES) {
        if (record.expiresAt <= Date.now()) VERIFIER_RETURN_NONCES.delete(nonce);
    }
    if (VERIFIER_RETURN_NONCES.size >= MAX_VERIFIER_RETURN_NONCES) {
        return res.status(503).json({ error: 'Verifier results are temporarily unavailable' });
    }

    const sessionHash = createHash('sha256')
        .update(session.sessionId, 'utf8')
        .digest('hex');
    const { token, payload } = createVerifierReturnToken({
        sessionHash,
        isAdult: session.isAdult === true,
        state: session.verifierState,
        secret: SESSION_SECRET,
    });
    VERIFIER_RETURN_NONCES.set(payload.nonce, {
        sessionHash,
        state: payload.state,
        expiresAt: payload.exp * 1000,
    });
    session.returnTokenIssued = true;
    session.returnToken = token;
    session.returnTokenNonce = payload.nonce;
    res.set('Cache-Control', 'no-store');
    return res.json({ token, state: payload.state });
});

app.get('/api/session/:sessionId/qr', async (req, res) => {
    const session = getSession(req.params.sessionId);
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    if (!session.loggedIn || session.verified || session.cancelled) {
        return res.status(409).json({ error: 'This session is not waiting for phone verification' });
    }
    if (configuredOrigin.protocol !== 'https:') {
        return res.status(503).json({ error: 'Phone verification requires HTTPS. Configure APP_ORIGIN with your HTTPS site URL.' });
    }

    const phoneUrl = new URL('/', ORIGIN);
    phoneUrl.searchParams.set('session', session.sessionId);
    phoneUrl.searchParams.set('mode', 'phone');
    const svg = await QRCode.toString(phoneUrl.toString(), {
        type: 'svg',
        errorCorrectionLevel: 'Q',
        margin: 2,
        width: 256,
    });

    res.set('Cache-Control', 'no-store');
    res.type('svg').send(svg);
});

app.post('/api/session/:sessionId/cancel', (req, res) => {
    if (rejectUnexpectedOrigin(req, res, 'Cancellation')) return;

    const session = getSession(req.params.sessionId);
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    if (!session.loggedIn) {
        return res.status(403).json({ error: 'Sign in on the requesting device before cancelling' });
    }

    const cancellationState = cancelVerificationSession(session);
    if (cancellationState === 'expired' || cancellationState === 'not-found') {
        return res.status(404).json({ error: 'Session not found or expired' });
    }
    if (cancellationState === 'used') {
        return res.status(409).json({ error: 'Verification is already in progress or complete' });
    }

    return res.json({ cancelled: true, returnTo: session.returnTo });
});

app.post('/api/passkey/register/options', async (req, res) => {
    if (rejectUnexpectedOrigin(req, res, 'Passkey registration')) return;
    if (!hasExactFields(req.body, [], ['qrToken'])) {
        return res.status(400).json({ error: 'Invalid passkey registration request' });
    }
    const context = getUserContext(req, res, req.body);
    if (!context) return;

    const supabase = getSupabaseAdmin();
    if (!supabase) {
        return res.status(503).json({ error: 'Passkey storage is not configured on the server' });
    }

    try {
        const { data: credentials, error } = await supabase
            .from('passkeys')
            .select('credential_id, transports')
            .eq('user_id', context.userId);
        if (error) {
            console.error('Could not load passkey credentials:', error.code || 'database error');
            return res.status(502).json({ error: 'Could not load passkey credentials' });
        }

        const options = await generateRegistrationOptions({
            rpName: 'BlindPass',
            rpID,
            userID: Buffer.from(context.userId, 'utf8'),
            userName: 'BlindPass account',
            userDisplayName: 'BlindPass account',
            timeout: 60_000,
            attestationType: 'none',
            excludeCredentials: (credentials || []).map((credential) => ({
                id: credential.credential_id,
                transports: Array.isArray(credential.transports)
                    ? credential.transports
                    : undefined,
            })),
            authenticatorSelection: {
                residentKey: 'required',
                userVerification: 'required',
            },
        });
        if (
            context.session &&
            (context.session.cancelled || context.session.expiresAt <= Date.now())
        ) {
            return res.status(context.session.cancelled ? 410 : 404).json({
                error: context.session.cancelled
                    ? 'This verification session was cancelled'
                    : 'Session not found or expired',
            });
        }
        const flowToken = issuePasskeyChallenge(PASSKEY_CHALLENGES, {
            challenge: options.challenge,
            ceremony: 'registration',
            userId: context.userId,
            sessionId: context.sessionId,
            sessionExpiresAt: context.session?.expiresAt,
        });
        res.set('Cache-Control', 'no-store');
        return res.json({ flowToken, options });
    } catch (error) {
        console.error(
            'Could not create passkey registration options:',
            error instanceof Error ? error.message : 'unknown error'
        );
        return res.status(500).json({ error: 'Could not start passkey registration' });
    }
});

app.post('/api/passkey/register/verify', async (req, res) => {
    if (rejectUnexpectedOrigin(req, res, 'Passkey registration')) return;
    if (!hasExactFields(req.body, ['flowToken', 'response'], ['qrToken'])) {
        return res.status(400).json({ error: 'Invalid passkey registration response' });
    }
    const context = getUserContext(req, res, req.body);
    if (!context) return;
    if (!req.body.response || typeof req.body.response !== 'object') {
        return res.status(400).json({ error: 'Invalid passkey registration response' });
    }

    const supabase = getSupabaseAdmin();
    if (!supabase) {
        return res.status(503).json({ error: 'Passkey storage is not configured on the server' });
    }
    const challenge = consumePasskeyChallenge(
        PASSKEY_CHALLENGES,
        req.body.flowToken,
        {
            ceremony: 'registration',
            userId: context.userId,
            sessionId: context.sessionId,
        }
    );
    if (!challenge) {
        return res.status(409).json({ error: 'Passkey registration challenge is missing, expired, or already used' });
    }

    let verification;
    try {
        verification = await verifyRegistrationResponse({
            response: req.body.response,
            expectedChallenge: challenge.challenge,
            expectedOrigin: ORIGIN,
            expectedRPID: rpID,
            requireUserVerification: true,
        });
    } catch {
        return res.status(400).json({ error: 'Passkey registration could not be verified' });
    }
    if (!verification.verified || !verification.registrationInfo.userVerified) {
        return res.status(400).json({ error: 'Passkey registration requires user verification' });
    }
    if (
        context.session &&
        (context.session.cancelled || context.session.expiresAt <= Date.now())
    ) {
        return res.status(410).json({ error: 'This verification session was cancelled or expired' });
    }

    const credential = verification.registrationInfo.credential;
    const responseTransports = req.body.response.response?.transports;
    const transports = Array.isArray(responseTransports)
        ? responseTransports.filter((transport) => typeof transport === 'string')
        : [];
    try {
        const { error } = await supabase.from('passkeys').insert({
            user_id: context.userId,
            credential_id: credential.id,
            public_key: Buffer.from(credential.publicKey).toString('base64url'),
            counter: credential.counter,
            transports,
        });
        if (error) {
            if (error.code === '23505') {
                return res.status(409).json({ error: 'This passkey is already registered' });
            }
            console.error('Could not store passkey credentials:', error.code || 'database error');
            return res.status(502).json({ error: 'Could not store the passkey' });
        }
        res.set('Cache-Control', 'no-store');
        return res.status(201).json({ registered: true });
    } catch (error) {
        console.error(
            'Could not store passkey credentials:',
            error instanceof Error ? error.message : 'unknown database error'
        );
        return res.status(502).json({ error: 'Could not store the passkey' });
    }
});

app.post('/api/passkey/login/options', async (req, res) => {
    if (rejectUnexpectedOrigin(req, res, 'Passkey login')) return;
    if (!hasExactFields(req.body, [], ['qrToken'])) {
        return res.status(400).json({ error: 'Invalid passkey login request' });
    }

    let session = null;
    if (req.body.qrToken !== undefined) {
        if (typeof req.body.qrToken !== 'string') {
            return res.status(400).json({ error: 'Invalid QR session token' });
        }
        session = getSession(req.body.qrToken);
        if (!session) return res.status(404).json({ error: 'Session not found or expired' });
        if (session.cancelled) return res.status(410).json({ error: 'This verification session was cancelled' });
        if (session.verified || session.verificationTokenUsed || session.verificationPending) {
            return res.status(409).json({ error: 'This verification session is already complete or in progress' });
        }
    }

    const supabase = getSupabaseAdmin();
    if (!supabase) {
        return res.status(503).json({ error: 'Passkey storage is not configured on the server' });
    }
    try {
        const options = await generateAuthenticationOptions({
            rpID,
            timeout: 60_000,
            userVerification: 'required',
            allowCredentials: [],
        });
        if (session && (session.cancelled || session.expiresAt <= Date.now())) {
            return res.status(session.cancelled ? 410 : 404).json({
                error: session.cancelled
                    ? 'This verification session was cancelled'
                    : 'Session not found or expired',
            });
        }
        const flowToken = issuePasskeyChallenge(PASSKEY_CHALLENGES, {
            challenge: options.challenge,
            ceremony: 'login',
            sessionId: session?.sessionId || null,
            sessionExpiresAt: session?.expiresAt,
        });
        res.set('Cache-Control', 'no-store');
        return res.json({ flowToken, options });
    } catch (error) {
        console.error(
            'Could not create passkey login options:',
            error instanceof Error ? error.message : 'unknown error'
        );
        return res.status(500).json({ error: 'Could not start passkey login' });
    }
});

app.post('/api/passkey/login/verify', async (req, res) => {
    if (rejectUnexpectedOrigin(req, res, 'Passkey login')) return;
    if (!hasExactFields(req.body, ['flowToken', 'assertion'], ['qrToken'])) {
        return res.status(400).json({ error: 'Invalid passkey login response' });
    }
    if (
        typeof req.body.flowToken !== 'string' ||
        !isValidAuthenticationResponse(req.body.assertion)
    ) {
        return res.status(400).json({ error: 'Invalid passkey login response' });
    }

    let session = null;
    const sessionId = req.body.qrToken || null;
    if (sessionId) {
        session = getSession(sessionId);
        if (!session) return res.status(404).json({ error: 'Session not found or expired' });
        if (session.cancelled) return res.status(410).json({ error: 'This verification session was cancelled' });
        if (session.verified || session.verificationTokenUsed || session.verificationPending) {
            return res.status(409).json({ error: 'This verification session is already complete or in progress' });
        }
    }

    const challenge = consumePasskeyChallenge(
        PASSKEY_CHALLENGES,
        req.body.flowToken,
        { ceremony: 'login', sessionId }
    );
    if (!challenge) {
        return res.status(409).json({ error: 'Passkey login challenge is missing, expired, or already used' });
    }
    const supabase = getSupabaseAdmin();
    if (!supabase) {
        return res.status(503).json({ error: 'Passkey storage is not configured on the server' });
    }

    let passkey;
    try {
        passkey = await resolvePasskeyCredential(supabase, req.body.assertion.id);
    } catch (error) {
        console.error(
            'Could not resolve passkey login credential:',
            error instanceof Error ? error.message : 'database error'
        );
        return res.status(502).json({ error: 'Could not resolve the passkey credential' });
    }
    if (
        !passkey ||
        !isValidUserId(passkey.user_id) ||
        !Number.isSafeInteger(Number(passkey.counter))
    ) {
        return res.status(401).json({ error: 'Passkey was not recognized' });
    }
    if (session?.userId && session.userId !== passkey.user_id) {
        return res.status(403).json({ error: 'This passkey belongs to another account' });
    }
    if (session && (session.cancelled || session.expiresAt <= Date.now())) {
        return res.status(session.cancelled ? 410 : 404).json({
            error: session.cancelled
                ? 'This verification session was cancelled'
                : 'Session not found or expired',
        });
    }

    let authentication;
    try {
        authentication = await verifyAuthenticationResponse({
            response: req.body.assertion,
            expectedChallenge: challenge.challenge,
            expectedOrigin: ORIGIN,
            expectedRPID: rpID,
            credential: {
                id: passkey.credential_id,
                publicKey: Buffer.from(passkey.public_key, 'base64url'),
                counter: Number(passkey.counter),
                transports: Array.isArray(passkey.transports) ? passkey.transports : undefined,
            },
            requireUserVerification: true,
        });
    } catch {
        return res.status(401).json({ error: 'Passkey authentication could not be verified' });
    }
    const userHandle = req.body.assertion.response.userHandle;
    if (
        !authentication.verified ||
        !authentication.authenticationInfo.userVerified ||
        authentication.authenticationInfo.credentialID !== passkey.credential_id ||
        (userHandle && userHandle !== Buffer.from(passkey.user_id, 'utf8').toString('base64url'))
    ) {
        return res.status(401).json({ error: 'Passkey authentication could not be verified' });
    }
    if (session && (session.cancelled || session.expiresAt <= Date.now())) {
        return res.status(session.cancelled ? 410 : 404).json({
            error: session.cancelled
                ? 'This verification session was cancelled'
                : 'Session not found or expired',
        });
    }

    try {
        const { data: updatedCredential, error: counterError } = await supabase
            .from('passkeys')
            .update({ counter: authentication.authenticationInfo.newCounter })
            .eq('id', passkey.id)
            .eq('counter', Number(passkey.counter))
            .select('id')
            .maybeSingle();
        if (counterError) {
            console.error('Could not update passkey login counter:', counterError.code || 'database error');
            return res.status(502).json({ error: 'Could not update passkey state' });
        }
        if (!updatedCredential) {
            return res.status(409).json({ error: 'This passkey was used concurrently. Try signing in again.' });
        }

        const account = await loadAccountSnapshot(supabase, passkey.user_id);
        if (session) {
            session.userId = passkey.user_id;
            session.loggedIn = true;
            session.provider = account.provider;
        }
        setAuthenticatedUserCookie(res, passkey.user_id);
        res.set('Cache-Control', 'no-store');
        return res.json({ loggedIn: true, hasPasskey: account.hasPasskey });
    } catch (error) {
        console.error(
            'Could not finish passkey login:',
            error instanceof Error ? error.message : 'database error'
        );
        return res.status(502).json({ error: 'Could not finish passkey login' });
    }
});

app.post('/api/verify/scanned-id/options', async (req, res) => {
    if (rejectUnexpectedOrigin(req, res, 'Phone ID verification')) return;
    if (!hasExactFields(req.body, ['qrToken'])) {
        return res.status(400).json({ error: 'Invalid phone verification request' });
    }
    const context = getUserContext(req, res, req.body);
    if (!context) return;
    if (!context.session) {
        return res.status(400).json({ error: 'Phone ID verification requires an active QR session' });
    }

    const supabase = getSupabaseAdmin();
    if (!supabase) {
        return res.status(503).json({ error: 'Passkey storage is not configured on the server' });
    }
    try {
        const { data: credentials, error } = await supabase
            .from('passkeys')
            .select('credential_id, transports')
            .eq('user_id', context.userId);
        if (error) {
            console.error('Could not load phone verification passkeys:', error.code || 'database error');
            return res.status(502).json({ error: 'Could not load passkey credentials' });
        }
        if (!credentials?.length) {
            return res.status(404).json({
                code: 'passkey-not-found',
                error: 'Register a passkey before completing phone verification',
            });
        }

        const options = await generateAuthenticationOptions({
            rpID,
            timeout: 60_000,
            userVerification: 'required',
            allowCredentials: credentials.map((credential) => ({
                id: credential.credential_id,
                transports: Array.isArray(credential.transports)
                    ? credential.transports
                    : undefined,
            })),
        });
        if (context.session.cancelled || context.session.expiresAt <= Date.now()) {
            return res.status(context.session.cancelled ? 410 : 404).json({
                error: context.session.cancelled
                    ? 'This verification session was cancelled'
                    : 'Session not found or expired',
            });
        }
        const flowToken = issuePasskeyChallenge(PASSKEY_CHALLENGES, {
            challenge: options.challenge,
            ceremony: 'scanned-id',
            userId: context.userId,
            sessionId: context.sessionId,
            sessionExpiresAt: context.session.expiresAt,
        });
        res.set('Cache-Control', 'no-store');
        return res.json({ flowToken, options });
    } catch (error) {
        console.error(
            'Could not create phone ID verification options:',
            error instanceof Error ? error.message : 'unknown error'
        );
        return res.status(500).json({ error: 'Could not start phone ID verification' });
    }
});

app.post('/api/verify/scanned-id', async (req, res) => {
    if (rejectUnexpectedOrigin(req, res, 'Phone ID verification')) return;
    if (!hasExactFields(req.body, [
        'qrToken',
        'flowToken',
        'assertion',
        'verified',
        'isAdult',
        'documentType',
        'issuingCountry',
        'expiresAt',
    ])) {
        return res.status(400).json({ error: 'Invalid phone verification response' });
    }
    if (
        typeof req.body.flowToken !== 'string' ||
        !isValidAuthenticationResponse(req.body.assertion)
    ) {
        return res.status(400).json({ error: 'Invalid phone verification response' });
    }
    const walletPayload = {
        qrToken: req.body.qrToken,
        verified: req.body.verified,
        isAdult: req.body.isAdult,
        documentType: req.body.documentType,
        issuingCountry: req.body.issuingCountry,
        expiresAt: req.body.expiresAt,
    };
    const validation = validateWalletSavePayload(walletPayload, ISSUING_COUNTRY_CODES);
    if (!validation.ok) {
        return res.status(400).json({ error: 'The locally verified ID outcome is invalid or expired' });
    }
    const context = getUserContext(req, res, req.body);
    if (!context) return;
    if (!context.session) {
        return res.status(400).json({ error: 'Phone ID verification requires an active QR session' });
    }
    const challenge = consumePasskeyChallenge(
        PASSKEY_CHALLENGES,
        req.body.flowToken,
        {
            ceremony: 'scanned-id',
            userId: context.userId,
            sessionId: context.sessionId,
        }
    );
    if (!challenge) {
        return res.status(409).json({ error: 'Phone verification challenge is missing, expired, or already used' });
    }

    const supabase = getSupabaseAdmin();
    if (!supabase) {
        return res.status(503).json({ error: 'Phone verification storage is not configured' });
    }
    let passkey;
    try {
        const { data, error } = await supabase
            .from('passkeys')
            .select('id, user_id, credential_id, public_key, counter, transports')
            .eq('user_id', context.userId)
            .eq('credential_id', req.body.assertion.id)
            .maybeSingle();
        if (error) throw error;
        passkey = data;
    } catch (error) {
        console.error(
            'Could not load phone verification passkey:',
            error instanceof Error ? error.message : 'database error'
        );
        return res.status(502).json({ error: 'Could not load the passkey credential' });
    }
    if (!passkey || !Number.isSafeInteger(Number(passkey.counter))) {
        return res.status(401).json({ error: 'This account passkey was not recognized' });
    }

    const tokenState = claimVerificationToken(context.session);
    if (tokenState === 'expired' || tokenState === 'not-found') {
        return res.status(404).json({ error: 'Session not found or expired' });
    }
    if (tokenState === 'cancelled') {
        return res.status(410).json({ error: 'This verification session was cancelled' });
    }
    if (tokenState === 'used') {
        return res.status(409).json({ error: 'This verification token has already been used' });
    }

    let authentication;
    try {
        authentication = await verifyAuthenticationResponse({
            response: req.body.assertion,
            expectedChallenge: challenge.challenge,
            expectedOrigin: ORIGIN,
            expectedRPID: rpID,
            credential: {
                id: passkey.credential_id,
                publicKey: Buffer.from(passkey.public_key, 'base64url'),
                counter: Number(passkey.counter),
                transports: Array.isArray(passkey.transports) ? passkey.transports : undefined,
            },
            requireUserVerification: true,
        });
    } catch {
        context.session.verificationPending = false;
        return res.status(401).json({ error: 'Phone verification passkey could not be verified' });
    }
    if (
        !authentication.verified ||
        !authentication.authenticationInfo.userVerified ||
        authentication.authenticationInfo.credentialID !== passkey.credential_id
    ) {
        context.session.verificationPending = false;
        return res.status(401).json({ error: 'Phone verification passkey could not be verified' });
    }
    if (context.session.cancelled || context.session.expiresAt <= Date.now()) {
        context.session.verificationPending = false;
        return res.status(context.session.cancelled ? 410 : 404).json({
            error: context.session.cancelled
                ? 'This verification session was cancelled'
                : 'Session not found or expired',
        });
    }

    try {
        const { data: updatedCredential, error: counterError } = await supabase
            .from('passkeys')
            .update({ counter: authentication.authenticationInfo.newCounter })
            .eq('id', passkey.id)
            .eq('counter', Number(passkey.counter))
            .select('id')
            .maybeSingle();
        if (counterError) {
            context.session.verificationPending = false;
            console.error('Could not update phone verification passkey counter:', counterError.code || 'database error');
            return res.status(502).json({ error: 'Could not update passkey state' });
        }
        if (!updatedCredential) {
            context.session.verificationPending = false;
            return res.status(409).json({ error: 'This passkey was used concurrently. Try again.' });
        }

        const verifiedAt = new Date().toISOString();
        const { error: walletError } = await supabase
            .from('wallet_credentials')
            .upsert(
                createWalletCredentialRecord(context.userId, validation.credential, verifiedAt),
                { onConflict: 'user_id' }
            );
        if (walletError) {
            context.session.verificationPending = false;
            console.error('Could not save phone-scanned Wallet credential:', walletError.code || 'database error');
            return res.status(502).json({ error: 'Could not save the verified Wallet badge' });
        }

        const outcome = {
            verified: true,
            documentType: validation.credential.documentType,
            issuingCountry: validation.credential.issuingCountry,
            isAdult: validation.credential.isAdult,
        };
        const sessionTokenHash = createHash('sha256')
            .update(context.session.sessionId, 'utf8')
            .digest('hex');
        const { error: insertError } = await supabase
            .from('verifications')
            .insert(createVerificationRecord(outcome, sessionTokenHash, verifiedAt));
        if (insertError) {
            context.session.verificationPending = false;
            if (insertError.code === '23505') {
                context.session.verificationTokenUsed = true;
                return res.status(409).json({ error: 'This verification token has already been used' });
            }
            console.error('Could not save phone-scanned verification:', insertError.code || 'database error');
            return res.status(502).json({ error: 'Could not save the verification result' });
        }

        context.session.verificationPending = false;
        context.session.verificationTokenUsed = true;
        context.session.verified = true;
        context.session.isOver18 = validation.credential.isAdult;
        context.session.documentType = validation.credential.documentType;
        context.session.issuingCountry = validation.credential.issuingCountry;
        context.session.isAdult = validation.credential.isAdult;
        context.session.verifiedAt = Date.now();
        res.set('Cache-Control', 'no-store');
        return res.status(201).json({
            verified: true,
            isAdult: validation.credential.isAdult,
        });
    } catch (error) {
        context.session.verificationPending = false;
        console.error(
            'Could not finish phone ID verification:',
            error instanceof Error ? error.message : 'database error'
        );
        return res.status(502).json({ error: 'Could not save the verification result' });
    }
});

app.post('/api/verify/wallet/options', async (req, res) => {
    if (rejectUnexpectedOrigin(req, res, 'Wallet verification')) return;
    if (!hasExactFields(req.body, ['qrToken'])) {
        return res.status(400).json({ error: 'Invalid Wallet verification request' });
    }
    const context = getUserContext(req, res, req.body);
    if (!context) return;
    const supabase = getSupabaseAdmin();
    if (!supabase) {
        return res.status(503).json({ error: 'BlindPass Wallet storage is not configured' });
    }

    try {
        const [wallet, { data: credentials, error: credentialError }] = await Promise.all([
            loadWalletCredential(supabase, context.userId),
            supabase
                .from('passkeys')
                .select('credential_id, transports')
                .eq('user_id', context.userId),
        ]);
        if (credentialError) {
            console.error('Could not load Wallet passkeys:', credentialError.code || 'database error');
            return res.status(502).json({ error: 'Could not load Wallet passkeys' });
        }
        if (!formatWalletCredential(wallet)?.isEligibleForAgeGate) {
            return res.status(403).json({
                code: 'wallet-not-eligible',
                error: 'No current 18+ credential is available in this BlindPass Wallet',
            });
        }
        if (!credentials?.length) {
            return res.status(404).json({
                code: 'passkey-not-found',
                error: 'Register a passkey for this account before approving from Wallet',
            });
        }

        const options = await generateAuthenticationOptions({
            rpID,
            timeout: 60_000,
            userVerification: 'required',
            allowCredentials: credentials.map((credential) => ({
                id: credential.credential_id,
                transports: Array.isArray(credential.transports) ? credential.transports : undefined,
            })),
        });
        if (context.session.cancelled || context.session.expiresAt <= Date.now()) {
            return res.status(context.session.cancelled ? 410 : 404).json({
                error: context.session.cancelled
                    ? 'This verification session was cancelled'
                    : 'Session not found or expired',
            });
        }
        const flowToken = issuePasskeyChallenge(PASSKEY_CHALLENGES, {
            challenge: options.challenge,
            ceremony: 'wallet',
            userId: context.userId,
            sessionId: context.sessionId,
            sessionExpiresAt: context.session.expiresAt,
        });
        res.set('Cache-Control', 'no-store');
        return res.json({ flowToken, options });
    } catch (error) {
        console.error(
            'Could not create Wallet verification options:',
            error instanceof Error ? error.message : 'database error'
        );
        return res.status(502).json({ error: 'Could not start Wallet verification' });
    }
});

app.post('/api/verify/wallet', async (req, res) => {
    if (rejectUnexpectedOrigin(req, res, 'Wallet verification')) return;
    if (!hasExactFields(req.body, ['qrToken', 'flowToken', 'assertion'])) {
        return res.status(400).json({ error: 'Invalid Wallet verification response' });
    }
    if (
        typeof req.body.flowToken !== 'string' ||
        !isValidAuthenticationResponse(req.body.assertion)
    ) {
        return res.status(400).json({ error: 'Invalid Wallet verification response' });
    }
    const context = getUserContext(req, res, req.body);
    if (!context) return;
    const challenge = consumePasskeyChallenge(
        PASSKEY_CHALLENGES,
        req.body.flowToken,
        {
            ceremony: 'wallet',
            userId: context.userId,
            sessionId: context.sessionId,
        }
    );
    if (!challenge) {
        return res.status(409).json({ error: 'Wallet assertion challenge is missing, expired, or already used' });
    }

    const supabase = getSupabaseAdmin();
    if (!supabase) {
        return res.status(503).json({ error: 'BlindPass Wallet storage is not configured' });
    }
    let wallet;
    let passkey;
    try {
        const [walletResult, passkeyResult] = await Promise.all([
            loadWalletCredential(supabase, context.userId),
            supabase
                .from('passkeys')
                .select('id, user_id, credential_id, public_key, counter, transports')
                .eq('user_id', context.userId)
                .eq('credential_id', req.body.assertion.id)
                .maybeSingle(),
        ]);
        if (passkeyResult.error) throw passkeyResult.error;
        wallet = walletResult;
        passkey = passkeyResult.data;
    } catch (error) {
        console.error(
            'Could not load Wallet verification data:',
            error instanceof Error ? error.message : 'database error'
        );
        return res.status(502).json({ error: 'Could not load Wallet verification data' });
    }
    const approval = validateWalletApproval(wallet, passkey, context.userId);
    if (!approval.ok && approval.error === 'wallet-not-eligible') {
        return res.status(403).json({ error: 'This Wallet credential is not eligible or has expired' });
    }
    if (!approval.ok) {
        return res.status(401).json({ error: 'This account passkey was not recognized' });
    }

    const tokenState = claimVerificationToken(context.session);
    if (tokenState === 'expired' || tokenState === 'not-found') {
        return res.status(404).json({ error: 'Session not found or expired' });
    }
    if (tokenState === 'cancelled') {
        return res.status(410).json({ error: 'This verification session was cancelled' });
    }
    if (tokenState === 'used') {
        return res.status(409).json({ error: 'This verification token has already been used' });
    }

    let authentication;
    try {
        authentication = await verifyAuthenticationResponse({
            response: req.body.assertion,
            expectedChallenge: challenge.challenge,
            expectedOrigin: ORIGIN,
            expectedRPID: rpID,
            credential: {
                id: passkey.credential_id,
                publicKey: Buffer.from(passkey.public_key, 'base64url'),
                counter: Number(passkey.counter),
                transports: Array.isArray(passkey.transports) ? passkey.transports : undefined,
            },
            requireUserVerification: true,
        });
    } catch {
        context.session.verificationPending = false;
        return res.status(401).json({ error: 'Wallet passkey assertion could not be verified' });
    }
    if (
        !authentication.verified ||
        !authentication.authenticationInfo.userVerified ||
        authentication.authenticationInfo.credentialID !== passkey.credential_id
    ) {
        context.session.verificationPending = false;
        return res.status(401).json({ error: 'Wallet passkey assertion could not be verified' });
    }
    if (context.session.expiresAt <= Date.now()) {
        context.session.verificationPending = false;
        return res.status(404).json({ error: 'Session not found or expired' });
    }

    try {
        const { data: updatedCredential, error: counterError } = await supabase
            .from('passkeys')
            .update({ counter: authentication.authenticationInfo.newCounter })
            .eq('id', passkey.id)
            .eq('counter', Number(passkey.counter))
            .select('id')
            .maybeSingle();
        if (counterError) {
            context.session.verificationPending = false;
            console.error('Could not update Wallet passkey counter:', counterError.code || 'database error');
            return res.status(502).json({ error: 'Could not update passkey state' });
        }
        if (!updatedCredential) {
            context.session.verificationPending = false;
            return res.status(409).json({ error: 'This passkey was used concurrently. Start verification again.' });
        }
        const refreshedWallet = await loadWalletCredential(supabase, context.userId);
        const refreshedApproval = validateWalletApproval(
            refreshedWallet,
            passkey,
            context.userId
        );
        if (!refreshedApproval.ok || context.session.expiresAt <= Date.now()) {
            context.session.verificationPending = false;
            return res.status(403).json({ error: 'This Wallet credential is no longer eligible' });
        }
        const { outcome } = refreshedApproval;

        const sessionTokenHash = createHash('sha256')
            .update(context.session.sessionId, 'utf8')
            .digest('hex');
        const verifiedAt = new Date().toISOString();
        const { error: insertError } = await supabase
            .from('verifications')
            .insert(createVerificationRecord(outcome, sessionTokenHash, verifiedAt));
        if (insertError) {
            context.session.verificationPending = false;
            if (insertError.code === '23505') {
                context.session.verificationTokenUsed = true;
                return res.status(409).json({ error: 'This verification token has already been used' });
            }
            console.error('Could not save the Wallet verification:', insertError.code || 'database error');
            return res.status(502).json({ error: 'Could not save the Wallet verification' });
        }

        context.session.verificationPending = false;
        context.session.verificationTokenUsed = true;
        context.session.verified = true;
        context.session.isOver18 = true;
        context.session.documentType = outcome.documentType;
        context.session.issuingCountry = outcome.issuingCountry;
        context.session.isAdult = true;
        context.session.verifiedAt = Date.now();
        res.set('Cache-Control', 'no-store');
        return res.status(201).json({ verified: true });
    } catch (error) {
        context.session.verificationPending = false;
        console.error(
            'Could not finish Wallet verification:',
            error instanceof Error ? error.message : 'database error'
        );
        return res.status(502).json({ error: 'Could not save the Wallet verification' });
    }
});

app.get('/auth/callback', async (req, res) => {
    res.append(
        'Set-Cookie',
        clearOAuthStateCookie(configuredOrigin.protocol === 'https:')
    );
    if (req.query.error) {
        return res.status(400).send('OAuth sign-in was not completed. Return to BlindPass and try again.');
    }

    const state = String(req.query.state || '');
    const authState = OAUTH_STATES.get(state);
    OAUTH_STATES.delete(state);
    const cookieState = getCookieValue(req.get('cookie'), 'blindpass_oauth_state');
    if (
        !authState ||
        authState.expiresAt <= Date.now() ||
        !isSafeEqual(state, cookieState)
    ) {
        return res.status(400).send('The sign-in request expired. Return to BlindPass and try again.');
    }

    const session = authState.sessionId ? getSession(authState.sessionId) : null;
    if (authState.sessionId && !session) {
        return res.status(410).send('This verification session has expired. Start again from the requesting site.');
    }
    if (session?.cancelled) {
        return res.status(410).send('This verification session was cancelled.');
    }

    try {
        let subject;
        if (req.query.code) {
            const redirectUri = `${ORIGIN}/auth/callback`;
            const code = String(req.query.code);
            if (authState.provider === 'google') {
                if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
                    return res.status(503).send('Google sign-in is not configured on this server.');
                }
                subject = await exchangeGoogleCode(
                    code,
                    redirectUri,
                    authState.codeVerifier
                );
            } else {
                if (!MICROSOFT_CLIENT_ID || !MICROSOFT_CLIENT_SECRET) {
                    return res.status(503).send('Microsoft sign-in is not configured on this server.');
                }
                subject = await exchangeMicrosoftCode(
                    code,
                    redirectUri,
                    authState.codeVerifier
                );
            }
        } else if (req.query.demo === '1' && process.env.NODE_ENV !== 'production') {
            subject = `blindpass-local-demo:${authState.provider}`;
        } else {
            return res.status(400).send('OAuth sign-in did not return an authorization code.');
        }

        const supabase = getSupabaseAdmin();
        if (!supabase) {
            return res.status(503).send('BlindPass account storage is not configured on this server.');
        }
        const userId = await resolveOAuthUser(
            supabase,
            authState.provider,
            subject,
            OAUTH_SUBJECT_PEPPER
        );
        if (session?.userId && session.userId !== userId) {
            return res.status(409).send('This verification session is already connected to another account.');
        }
        if (session) {
            session.loggedIn = true;
            session.provider = authState.provider;
            session.userId = userId;
        }
        setAuthenticatedUserCookie(res, userId);
        const destination = session
            ? `/?session=${encodeURIComponent(session.sessionId)}`
            : '/';
        return res.redirect(303, destination);
    } catch (error) {
        console.error(
            'OAuth account sign-in failed:',
            error instanceof Error ? error.message : 'unknown error'
        );
        return res.status(502).send('Could not complete account sign-in. Return to BlindPass and try again.');
    }
});

app.get('/auth/:provider', (req, res) => {
    const provider = req.params.provider;
    if (!['google', 'microsoft'].includes(provider)) {
        return res.status(404).send('Sign-in provider not found.');
    }
    const rawSessionId = String(req.query.session || '');
    const session = rawSessionId ? getSession(rawSessionId) : null;
    if (rawSessionId && !session) {
        return res.status(404).send('Verification session not found or expired. Start again from the requesting site.');
    }
    if (session?.cancelled || session?.verified) {
        return res.status(409).send('This verification session is no longer available.');
    }

    for (const [oldState, record] of OAUTH_STATES) {
        if (record.expiresAt <= Date.now()) OAUTH_STATES.delete(oldState);
    }
    if (OAUTH_STATES.size >= MAX_OAUTH_STATES) {
        return res.status(503).send('Too many active sign-in requests. Try again shortly.');
    }
    const state = randomBytes(32).toString('base64url');
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256')
        .update(codeVerifier, 'utf8')
        .digest('base64url');
    OAUTH_STATES.set(state, {
        provider,
        codeVerifier,
        sessionId: session?.sessionId || null,
        expiresAt: Math.min(
            Date.now() + OAUTH_STATE_LIFETIME_MS,
            session?.expiresAt ?? Number.POSITIVE_INFINITY
        ),
    });
    const redirectUri = `${ORIGIN}/auth/callback`;

    if (provider === 'google' && GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
        const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        url.searchParams.set('client_id', GOOGLE_CLIENT_ID);
        url.searchParams.set('redirect_uri', redirectUri);
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('scope', 'openid');
        url.searchParams.set('state', state);
        url.searchParams.set('code_challenge', codeChallenge);
        url.searchParams.set('code_challenge_method', 'S256');
        res.append(
            'Set-Cookie',
            serializeOAuthStateCookie(state, configuredOrigin.protocol === 'https:')
        );
        return res.redirect(302, url.toString());
    }

    if (provider === 'microsoft' && MICROSOFT_CLIENT_ID && MICROSOFT_CLIENT_SECRET) {
        const url = new URL(`https://login.microsoftonline.com/${MICROSOFT_TENANT_ID}/oauth2/v2.0/authorize`);
        url.searchParams.set('client_id', MICROSOFT_CLIENT_ID);
        url.searchParams.set('redirect_uri', redirectUri);
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('scope', 'openid profile User.Read');
        url.searchParams.set('response_mode', 'query');
        url.searchParams.set('state', state);
        url.searchParams.set('code_challenge', codeChallenge);
        url.searchParams.set('code_challenge_method', 'S256');
        res.append(
            'Set-Cookie',
            serializeOAuthStateCookie(state, configuredOrigin.protocol === 'https:')
        );
        return res.redirect(302, url.toString());
    }

    if (process.env.NODE_ENV === 'production') {
        OAUTH_STATES.delete(state);
        return res.status(503).send(`${provider} sign-in is not configured on this server.`);
    }
    res.append(
        'Set-Cookie',
        serializeOAuthStateCookie(state, configuredOrigin.protocol === 'https:')
    );
    return res.redirect(302, `/auth/callback?state=${encodeURIComponent(state)}&demo=1`);
});

app.use((req, res) => {
    res.status(404).send('Not found');
});

app.listen(PORT, () => {
    console.log(`BlindPass running on ${ORIGIN}`);
    console.log(`Verifier start page: ${ORIGIN}/verifier.html`);
});