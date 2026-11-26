import test from 'node:test';
import assert from 'node:assert/strict';
import {
    cancelVerificationSession,
    claimVerificationToken,
    createVerificationRecord,
    resolveVerifierLaunch,
    safeReturnUrl,
} from '../server/verification.js';
import {
    createVerifierReturnToken,
    verifyVerifierReturnToken,
} from '../server/verifier-token.js';

test('resolves verifier names and return URLs from current and legacy launch parameters', () => {
    const appOrigin = 'https://blindpass.example';
    const allowedOrigins = new Set([appOrigin, 'https://discord.com', 'https://reddit.com']);
    assert.deepEqual(resolveVerifierLaunch({
        verifier: 'Discord',
        return_url: 'https://discord.com/verify?source=blindpass',
    }, '', appOrigin, allowedOrigins), {
        verifier: 'Discord',
        returnTo: 'https://discord.com/verify?source=blindpass',
    });

    assert.deepEqual(resolveVerifierLaunch({
        client: 'Reddit',
        return_to: 'https://reddit.com/verify',
    }, '', appOrigin, allowedOrigins), {
        verifier: 'Reddit',
        returnTo: 'https://reddit.com/verify',
    });
});

test('uses the referrer hostname as a display name and rejects unsafe return URLs', () => {
    const appOrigin = 'https://blindpass.example';
    const allowedOrigins = new Set([appOrigin, 'https://www.reddit.com']);
    assert.deepEqual(resolveVerifierLaunch({}, 'https://www.reddit.com/verify', appOrigin, allowedOrigins), {
        verifier: 'Reddit',
        returnTo: 'https://www.reddit.com/verify',
    });
    assert.deepEqual(resolveVerifierLaunch({
        verifier: 'Partner',
        return_url: 'https://attacker.example/redirect',
    }, '', appOrigin, allowedOrigins), {
        verifier: 'Partner',
        returnTo: null,
    });
    assert.equal(safeReturnUrl('javascript:alert(1)', appOrigin, allowedOrigins), null);
});

test('stores only non-PII outcome fields and a token hash', () => {
    const outcome = {
        verified: true,
        documentType: 'passport',
        issuingCountry: 'DEU',
        isAdult: true,
    };
    const record = createVerificationRecord(
        outcome,
        'sha256-token-hash',
        '2026-11-20T00:00:00.000Z'
    );

    assert.deepEqual(Object.keys(record).sort(), [
        'document_type',
        'is_adult',
        'is_over_18',
        'issuing_country',
        'session_token_hash',
        'verified',
        'verified_at',
    ]);
    assert.equal(record.session_token_hash, 'sha256-token-hash');
    assert.equal('token' in record, false);
    assert.equal('dateOfBirth' in record, false);
    assert.equal('documentNumber' in record, false);
    assert.equal('fullName' in record, false);
});

test('claims a valid session token once and rejects expired or repeated claims', () => {
    const session = {
        expiresAt: 2000,
        verified: false,
        verificationTokenUsed: false,
        verificationPending: false,
    };

    assert.equal(claimVerificationToken(session, 1000), null);
    assert.equal(session.verificationPending, true);
    assert.equal(claimVerificationToken(session, 1000), 'used');
    assert.equal(claimVerificationToken({ ...session, expiresAt: 1000 }, 1000), 'expired');
});

test('cancels a pending session and prevents it from being verified', () => {
    const session = {
        expiresAt: 2000,
        verified: false,
        verificationTokenUsed: false,
        verificationPending: false,
        cancelled: false,
    };

    assert.equal(cancelVerificationSession(session, 1000), null);
    assert.equal(session.cancelled, true);
    assert.equal(cancelVerificationSession(session, 1000), 'cancelled');
    assert.equal(claimVerificationToken(session, 1000), 'cancelled');
});

test('does not cancel expired, claimed, or completed sessions', () => {
    assert.equal(cancelVerificationSession({ expiresAt: 1000 }, 1000), 'expired');

    const claimedSession = {
        expiresAt: 2000,
        verified: false,
        verificationTokenUsed: false,
        verificationPending: true,
        cancelled: false,
    };
    assert.equal(cancelVerificationSession(claimedSession, 1000), 'used');
    assert.equal(claimedSession.cancelled, false);

    const completedSession = {
        expiresAt: 2000,
        verified: true,
        verificationTokenUsed: true,
        verificationPending: false,
        cancelled: false,
    };
    assert.equal(cancelVerificationSession(completedSession, 1000), 'used');
    assert.equal(completedSession.cancelled, false);
});

test('signs short-lived verifier results, binds state, and consumes each nonce once', () => {
    const secret = 'verifier-test-secret-that-is-long-enough';
    const state = 'verifier-state-1234567890';
    const now = 1_000_000;
    const { token, payload } = createVerifierReturnToken({
        sessionHash: 'a'.repeat(64),
        isAdult: true,
        state,
        secret,
        now,
    });
    const nonces = new Map([[payload.nonce, {
        sessionHash: payload.session_hash,
        state,
        expiresAt: payload.exp * 1000,
    }]]);
    const verify = (testToken = token, expectedState = state, at = now) => (
        verifyVerifierReturnToken(testToken, {
            secret,
            expectedState,
            pendingNonces: nonces,
            now: at,
        })
    );

    assert.equal(verify().is_adult, true);
    assert.equal(verify(), null);

    const second = createVerifierReturnToken({
        sessionHash: 'b'.repeat(64),
        isAdult: false,
        state,
        secret,
        now,
    });
    nonces.set(second.payload.nonce, {
        sessionHash: second.payload.session_hash,
        state,
        expiresAt: second.payload.exp * 1000,
    });
    assert.equal(verify(second.token, 'different-state-123456'), null);
    assert.equal(verify(`${second.token}x`), null);
    assert.equal(verify(second.token, state, now + 181_000), null);
});
