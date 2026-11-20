import test from 'node:test';
import assert from 'node:assert/strict';
import {
    generateAuthenticationOptions,
    generateRegistrationOptions,
} from '@simplewebauthn/server';
import {
    consumePasskeyChallenge,
    isValidAuthenticationResponse,
    isValidUserId,
    issuePasskeyChallenge,
    PASSKEY_CHALLENGE_TTL_MS,
} from '../server/passkeys.js';
import {
    clearUserSessionCookie,
    readUserSessionCookie,
    serializeUserSessionCookie,
} from '../server/auth.js';
import { resolvePasskeyCredential } from '../server/accounts.js';
import { resolveWebAuthnConfig } from '../server/webauthn-config.js';

const userId = 'c0a80123-4567-489a-bcde-1234567890ab';

test('uses localhost as the development WebAuthn fallback', () => {
    const config = resolveWebAuthnConfig({ port: 3000 });
    assert.equal(config.expectedOrigin, 'http://localhost:3000');
    assert.equal(config.rpID, 'localhost');
});

test('derives the RP ID from configured ngrok and Render origins', () => {
    const ngrok = resolveWebAuthnConfig({
        appOrigin: 'https://lyricist-graceless-excuse.ngrok-free.dev',
    });
    assert.equal(ngrok.expectedOrigin, 'https://lyricist-graceless-excuse.ngrok-free.dev');
    assert.equal(ngrok.rpID, 'lyricist-graceless-excuse.ngrok-free.dev');

    const render = resolveWebAuthnConfig({
        renderExternalUrl: 'https://blindpass.onrender.com',
    });
    assert.equal(render.expectedOrigin, 'https://blindpass.onrender.com');
    assert.equal(render.rpID, 'blindpass.onrender.com');
});

test('rejects invalid or unrelated relying-party domains', () => {
    assert.throws(
        () => resolveWebAuthnConfig({
            appOrigin: 'https://blindpass.onrender.com',
            rpID: 'other.example.com',
        }),
        /RP_ID must match APP_ORIGIN/
    );
    assert.throws(
        () => resolveWebAuthnConfig({
            appOrigin: 'http://example.com',
        }),
        /APP_ORIGIN must be an HTTPS origin/
    );
    assert.throws(
        () => resolveWebAuthnConfig({ nodeEnv: 'production' }),
        /APP_ORIGIN or RENDER_EXTERNAL_URL must be configured/
    );
});

test('registration binds a discoverable credential to the account UUID', async () => {
    const registration = await generateRegistrationOptions({
        rpName: 'BlindPass',
        rpID: 'localhost',
        userID: Buffer.from(userId, 'utf8'),
        userName: 'BlindPass account',
        authenticatorSelection: {
            residentKey: 'required',
            userVerification: 'required',
        },
    });

    assert.equal(registration.authenticatorSelection.userVerification, 'required');
    assert.equal(registration.authenticatorSelection.residentKey, 'required');
});

test('discoverable passkey login leaves allowCredentials empty and resolves the credential owner', async () => {
    const authentication = await generateAuthenticationOptions({
        rpID: 'localhost',
        userVerification: 'required',
        allowCredentials: [],
    });
    assert.deepEqual(authentication.allowCredentials, []);
    assert.equal(authentication.userVerification, 'required');

    const passkey = {
        id: 'opaque-row-id',
        user_id: userId,
        credential_id: 'credential-id',
        public_key: 'cHVibGljLWtleQ',
        counter: 1,
        transports: ['internal'],
    };
    const supabase = {
        from(table) {
            assert.equal(table, 'passkeys');
            return {
                select(columns) {
                    assert.equal(columns, 'id, user_id, credential_id, public_key, counter, transports');
                    return this;
                },
                eq(column, value) {
                    assert.equal(column, 'credential_id');
                    assert.equal(value, passkey.credential_id);
                    return this;
                },
                async maybeSingle() {
                    return { data: passkey, error: null };
                },
            };
        },
    };
    assert.deepEqual(await resolvePasskeyCredential(supabase, 'credential-id'), passkey);
});

test('binds passkey flow challenges to one ceremony, user, session, and use', () => {
    const challenges = new Map();
    const flowToken = issuePasskeyChallenge(challenges, {
        challenge: 'challenge-one',
        ceremony: 'wallet',
        userId,
        sessionId: 'session-one',
        sessionExpiresAt: 20_000,
    }, 10_000);

    assert.equal(consumePasskeyChallenge(challenges, flowToken, {
        ceremony: 'wallet',
        userId,
        sessionId: 'session-one',
    }, 10_001).challenge, 'challenge-one');
    assert.equal(consumePasskeyChallenge(challenges, flowToken, {
        ceremony: 'wallet',
        userId,
        sessionId: 'session-one',
    }, 10_001), null);

    const wrongUserToken = issuePasskeyChallenge(challenges, {
        challenge: 'challenge-two',
        ceremony: 'registration',
        userId,
    }, 10_000);
    assert.equal(consumePasskeyChallenge(challenges, wrongUserToken, {
        ceremony: 'registration',
        userId: 'c0a80123-4567-489a-bcde-1234567890ac',
    }, 10_001), null);

    const expiredToken = issuePasskeyChallenge(challenges, {
        challenge: 'challenge-three',
        ceremony: 'login',
    }, 10_000);
    assert.equal(consumePasskeyChallenge(challenges, expiredToken, {
        ceremony: 'login',
    }, 10_000 + PASSKEY_CHALLENGE_TTL_MS), null);
});

test('signs account cookies, rejects tampering and expiration, and clears cookies', () => {
    const secret = '0123456789abcdef0123456789abcdef';
    const now = 1_000_000;
    const cookie = serializeUserSessionCookie(userId, secret, true, now);
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /SameSite=Lax/);
    assert.match(cookie, /Secure/);
    assert.equal(readUserSessionCookie(`other=1; ${cookie}`, secret, now), userId);

    const value = cookie.split(';')[0];
    const [name, signedValue] = value.split('=');
    assert.equal(readUserSessionCookie(`${name}=${signedValue}x`, secret, now), null);
    assert.equal(
        readUserSessionCookie(cookie, secret, now + 30 * 24 * 60 * 60 * 1000),
        null
    );
    assert.match(clearUserSessionCookie(false), /Max-Age=0/);
});

test('accepts only structurally valid UUIDs and WebAuthn assertions', () => {
    assert.equal(isValidUserId(userId), true);
    assert.equal(isValidUserId('not-a-user-id'), false);

    const assertion = {
        id: 'credential',
        rawId: 'credential',
        type: 'public-key',
        response: {
            authenticatorData: 'authenticator-data',
            clientDataJSON: 'client-data',
            signature: 'signature',
        },
    };
    assert.equal(isValidAuthenticationResponse(assertion), true);
    assert.equal(isValidAuthenticationResponse({ ...assertion, rawId: 'different' }), false);
});
