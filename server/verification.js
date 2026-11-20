function getStringQueryValue(value) {
    return typeof value === 'string' ? value.trim() : '';
}

function getHostnameLabel(value) {
    if (!value) return '';
    try {
        const hostname = new URL(value).hostname.replace(/^www\./i, '');
        const labels = hostname.split('.');
        const label = labels.length > 1 ? labels.at(-2) : labels[0];
        return label ? `${label[0].toUpperCase()}${label.slice(1)}` : '';
    } catch {
        return '';
    }
}

export function safeReturnUrl(rawUrl, origin, allowedOrigins) {
    if (typeof rawUrl !== 'string' || !rawUrl.trim()) return null;
    try {
        const parsed = new URL(rawUrl, origin);
        if (
            !['http:', 'https:'].includes(parsed.protocol) ||
            !allowedOrigins.has(parsed.origin) ||
            parsed.username ||
            parsed.password ||
            parsed.pathname === '/start' ||
            parsed.pathname.startsWith('/auth/')
        ) {
            return null;
        }
        return parsed.toString();
    } catch {
        return null;
    }
}

export function resolveVerifierLaunch(query, referrer, origin, allowedOrigins) {
    const requestedReturnUrl =
        getStringQueryValue(query.return_url) ||
        getStringQueryValue(query.return_to) ||
        getStringQueryValue(referrer);
    const returnTo = safeReturnUrl(requestedReturnUrl, origin, allowedOrigins);
    const verifier =
        getStringQueryValue(query.verifier) ||
        getStringQueryValue(query.client) ||
        getHostnameLabel(requestedReturnUrl) ||
        'Verifier';
    return {
        verifier: verifier.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 80) || 'Verifier',
        returnTo,
    };
}

export function createVerificationRecord(outcome, sessionTokenHash, verifiedAt) {
    return {
        verified: outcome.verified,
        document_type: outcome.documentType,
        issuing_country: outcome.issuingCountry,
        is_adult: outcome.isAdult,
        is_over_18: outcome.isAdult,
        session_token_hash: sessionTokenHash,
        verified_at: verifiedAt,
    };
}

export function claimVerificationToken(session, now = Date.now()) {
    if (!session) return 'not-found';
    if (!Number.isFinite(session.expiresAt) || session.expiresAt <= now) return 'expired';
    if (session.cancelled) return 'cancelled';
    if (session.verified || session.verificationTokenUsed || session.verificationPending) {
        return 'used';
    }

    session.verificationPending = true;
    return null;
}

export function cancelVerificationSession(session, now = Date.now()) {
    if (!session) return 'not-found';
    if (!Number.isFinite(session.expiresAt) || session.expiresAt <= now) return 'expired';
    if (session.cancelled) return 'cancelled';
    if (session.verified || session.verificationTokenUsed || session.verificationPending) {
        return 'used';
    }

    session.cancelled = true;
    return null;
}
