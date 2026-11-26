import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const VERIFIER_TOKEN_TTL_SECONDS = 3 * 60;

function sign(payload, secret) {
    return createHmac('sha256', secret).update(payload).digest('base64url');
}

function safeEqual(left, right) {
    const leftBuffer = Buffer.from(left);
    const rightBuffer = Buffer.from(right);
    return leftBuffer.length === rightBuffer.length &&
        timingSafeEqual(leftBuffer, rightBuffer);
}

export function createVerifierReturnToken({
    sessionHash,
    isAdult,
    state,
    secret,
    now = Date.now(),
    ttlSeconds = VERIFIER_TOKEN_TTL_SECONDS,
}) {
    if (
        typeof secret !== 'string' ||
        secret.length < 32 ||
        !/^[0-9a-f]{64}$/.test(sessionHash) ||
        typeof isAdult !== 'boolean' ||
        typeof state !== 'string' ||
        !/^[A-Za-z0-9_-]{16,128}$/.test(state) ||
        !Number.isSafeInteger(ttlSeconds) ||
        ttlSeconds < 1 ||
        ttlSeconds > VERIFIER_TOKEN_TTL_SECONDS
    ) {
        throw new Error('Invalid verifier return token data');
    }

    const issuedAt = Math.floor(now / 1000);
    const payload = {
        session_hash: sessionHash,
        is_adult: isAdult,
        state,
        nonce: randomBytes(32).toString('base64url'),
        iat: issuedAt,
        exp: issuedAt + ttlSeconds,
    };
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    return {
        token: `${encodedPayload}.${sign(encodedPayload, secret)}`,
        payload,
    };
}

export function verifyVerifierReturnToken(
    token,
    { secret, expectedState, pendingNonces, now = Date.now() }
) {
    if (
        typeof token !== 'string' ||
        token.length > 2048 ||
        typeof secret !== 'string' ||
        typeof expectedState !== 'string' ||
        !(pendingNonces instanceof Map)
    ) {
        return null;
    }

    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [encodedPayload, signature] = parts;
    if (!encodedPayload || !signature) return null;
    if (!safeEqual(sign(encodedPayload, secret), signature)) return null;

    let payload;
    try {
        payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    } catch {
        return null;
    }

    const nowSeconds = Math.floor(now / 1000);
    if (
        !payload ||
        !/^[0-9a-f]{64}$/.test(payload.session_hash) ||
        typeof payload.is_adult !== 'boolean' ||
        typeof payload.state !== 'string' ||
        !/^[A-Za-z0-9_-]{16,128}$/.test(payload.state) ||
        typeof payload.nonce !== 'string' ||
        !/^[A-Za-z0-9_-]{43}$/.test(payload.nonce) ||
        !Number.isSafeInteger(payload.iat) ||
        !Number.isSafeInteger(payload.exp) ||
        payload.iat > nowSeconds + 30 ||
        payload.exp <= nowSeconds ||
        payload.exp <= payload.iat ||
        payload.exp - payload.iat > VERIFIER_TOKEN_TTL_SECONDS ||
        !safeEqual(payload.state, expectedState)
    ) {
        return null;
    }

    const issuedNonce = pendingNonces.get(payload.nonce);
    if (
        !issuedNonce ||
        issuedNonce.expiresAt <= now ||
        issuedNonce.sessionHash !== payload.session_hash ||
        !safeEqual(issuedNonce.state, payload.state)
    ) {
        return null;
    }

    pendingNonces.delete(payload.nonce);
    return payload;
}
