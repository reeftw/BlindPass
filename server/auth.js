import { createHmac, timingSafeEqual } from 'node:crypto';
import { isValidUserId } from './passkeys.js';

export const USER_SESSION_COOKIE = 'blindpass_session';
export const USER_SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;

function signPayload(payload, secret) {
    return createHmac('sha256', secret).update(payload).digest('base64url');
}

export function createUserSessionCookie(userId, secret, now = Date.now()) {
    if (!isValidUserId(userId)) throw new Error('Invalid account user ID');
    const payload = Buffer.from(JSON.stringify({
        userId,
        expiresAt: Math.floor(now / 1000) + USER_SESSION_TTL_SECONDS,
    })).toString('base64url');
    return `${payload}.${signPayload(payload, secret)}`;
}

export function readUserSessionCookie(cookieHeader, secret, now = Date.now()) {
    if (typeof cookieHeader !== 'string') return null;
    const cookie = cookieHeader.split(';')
        .map((part) => part.trim())
        .find((part) => part.startsWith(`${USER_SESSION_COOKIE}=`));
    if (!cookie) return null;

    const [payload, signature, extra] = cookie
        .slice(USER_SESSION_COOKIE.length + 1)
        .split('.');
    if (!payload || !signature || extra) return null;

    const expectedSignature = Buffer.from(signPayload(payload, secret));
    const receivedSignature = Buffer.from(signature);
    if (
        expectedSignature.length !== receivedSignature.length ||
        !timingSafeEqual(expectedSignature, receivedSignature)
    ) {
        return null;
    }

    try {
        const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
        if (
            !isValidUserId(session.userId) ||
            !Number.isSafeInteger(session.expiresAt) ||
            session.expiresAt <= Math.floor(now / 1000)
        ) {
            return null;
        }
        return session.userId;
    } catch {
        return null;
    }
}

export function serializeUserSessionCookie(userId, secret, secure, now = Date.now()) {
    const value = createUserSessionCookie(userId, secret, now);
    const secureAttribute = secure ? '; Secure' : '';
    return `${USER_SESSION_COOKIE}=${value}; Path=/; Max-Age=${USER_SESSION_TTL_SECONDS}; HttpOnly; SameSite=Lax${secureAttribute}`;
}

export function clearUserSessionCookie(secure) {
    const secureAttribute = secure ? '; Secure' : '';
    return `${USER_SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${secureAttribute}`;
}
