import { randomBytes } from 'node:crypto';

export const PASSKEY_CHALLENGE_TTL_MS = 5 * 60 * 1000;

const USER_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isValidUserId(value) {
    return typeof value === 'string' && USER_ID_PATTERN.test(value);
}

export function isValidAuthenticationResponse(assertion) {
    return Boolean(
        assertion &&
        typeof assertion === 'object' &&
        !Array.isArray(assertion) &&
        typeof assertion.id === 'string' &&
        assertion.id === assertion.rawId &&
        assertion.type === 'public-key' &&
        assertion.response &&
        typeof assertion.response === 'object' &&
        !Array.isArray(assertion.response) &&
        ['authenticatorData', 'clientDataJSON', 'signature'].every(
            (field) => typeof assertion.response[field] === 'string'
        )
    );
}

export function issuePasskeyChallenge(
    challenges,
    {
        challenge,
        ceremony,
        userId = null,
        sessionId = null,
        sessionExpiresAt = Number.POSITIVE_INFINITY,
    },
    now = Date.now()
) {
    const flowToken = randomBytes(32).toString('base64url');
    challenges.set(flowToken, {
        challenge,
        ceremony,
        userId,
        sessionId,
        expiresAt: Math.min(sessionExpiresAt, now + PASSKEY_CHALLENGE_TTL_MS),
    });
    return flowToken;
}

export function consumePasskeyChallenge(
    challenges,
    flowToken,
    { ceremony, userId = null, sessionId = null },
    now = Date.now()
) {
    const state = challenges.get(flowToken);
    challenges.delete(flowToken);
    if (
        !state ||
        state.ceremony !== ceremony ||
        state.userId !== userId ||
        state.sessionId !== sessionId ||
        state.expiresAt <= now
    ) {
        return null;
    }

    return state;
}

export function clearExpiredPasskeyChallenges(challenges, now = Date.now()) {
    for (const [flowToken, state] of challenges) {
        if (state.expiresAt <= now) challenges.delete(flowToken);
    }
}
