const WALLET_SAVE_FIELDS = new Set([
    'qrToken',
    'verified',
    'isAdult',
    'documentType',
    'issuingCountry',
    'expiresAt',
]);

export function validateWalletSavePayload(body, issuingCountryCodes, now = Date.now()) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
        return { ok: false, error: 'invalid-payload' };
    }
    const keys = Object.keys(body);
    if (
        keys.some((key) => !WALLET_SAVE_FIELDS.has(key)) ||
        keys.length !== WALLET_SAVE_FIELDS.size - (body.qrToken === undefined ? 1 : 0)
    ) {
        return { ok: false, error: 'invalid-payload' };
    }
    if (
        body.verified !== true ||
        typeof body.isAdult !== 'boolean' ||
        !['passport', 'id-card'].includes(body.documentType) ||
        typeof body.issuingCountry !== 'string' ||
        !issuingCountryCodes.has(body.issuingCountry) ||
        typeof body.expiresAt !== 'string' ||
        !/^\d{4}-\d{2}-\d{2}$/.test(body.expiresAt)
    ) {
        return { ok: false, error: 'invalid-wallet-credential' };
    }

    const expiryDate = new Date(`${body.expiresAt}T23:59:59.999Z`);
    if (
        Number.isNaN(expiryDate.getTime()) ||
        expiryDate.toISOString().slice(0, 10) !== body.expiresAt ||
        expiryDate.getTime() <= now
    ) {
        return { ok: false, error: 'expired-document' };
    }

    return {
        ok: true,
        credential: {
            verified: true,
            isAdult: body.isAdult,
            documentType: body.documentType,
            issuingCountry: body.issuingCountry,
            expiresAt: expiryDate.toISOString(),
        },
    };
}

export function createWalletCredentialRecord(userId, credential, verifiedAt) {
    return {
        user_id: userId,
        verified: credential.verified,
        is_adult: credential.isAdult,
        document_type: credential.documentType,
        issuing_country: credential.issuingCountry,
        verified_at: verifiedAt,
        expires_at: credential.expiresAt,
    };
}

export function formatWalletCredential(row, now = Date.now()) {
    if (!row) return null;
    const isCurrent = row.verified === true && Date.parse(row.expires_at) > now;
    return {
        verified: row.verified === true,
        isAdult: row.is_adult === true,
        documentType: row.document_type,
        issuingCountry: row.issuing_country,
        verifiedAt: row.verified_at,
        expiresAt: row.expires_at,
        isCurrent,
        isEligibleForAgeGate: isCurrent && row.is_adult === true,
    };
}

export function getWalletVerificationOutcome(row, now = Date.now()) {
    const wallet = formatWalletCredential(row, now);
    if (!wallet?.isEligibleForAgeGate) return null;
    return {
        verified: true,
        documentType: wallet.documentType,
        issuingCountry: wallet.issuingCountry,
        isAdult: true,
    };
}

export function validateWalletApproval(walletRow, passkey, userId, now = Date.now()) {
    const outcome = getWalletVerificationOutcome(walletRow, now);
    if (!outcome) return { ok: false, error: 'wallet-not-eligible' };
    if (
        !passkey ||
        passkey.user_id !== userId ||
        !Number.isSafeInteger(Number(passkey.counter))
    ) {
        return { ok: false, error: 'passkey-not-found' };
    }
    return { ok: true, outcome };
}
