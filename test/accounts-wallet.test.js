import test from 'node:test';
import assert from 'node:assert/strict';
import {
    hashOAuthSubject,
    resolveOAuthUser,
} from '../server/accounts.js';
import {
    createWalletCredentialRecord,
    formatWalletCredential,
    getWalletVerificationOutcome,
    validateWalletSavePayload,
    validateWalletApproval,
} from '../server/wallet.js';
import { claimVerificationToken, createVerificationRecord } from '../server/verification.js';

const userId = 'c0a80123-4567-489a-bcde-1234567890ab';
const countryCodes = new Set(['DEU', 'GBR', 'USA']);

test('hashes OAuth provider subjects and stores no raw subject identifier', async () => {
    const rawSubject = 'provider-account-subject';
    const expectedHash = hashOAuthSubject('google', rawSubject);
    assert.match(expectedHash, /^[0-9a-f]{64}$/);
    assert.notEqual(expectedHash, rawSubject);
    assert.notEqual(expectedHash, hashOAuthSubject('microsoft', rawSubject));

    let storedUser;
    const supabase = {
        from(table) {
            assert.equal(table, 'users');
            return {
                select() { return this; },
                eq(column, value) {
                    assert.equal(column, 'oauth_subject_hash');
                    assert.equal(value, expectedHash);
                    return this;
                },
                async maybeSingle() {
                    return { data: null, error: null };
                },
                insert(record) {
                    storedUser = record;
                    return this;
                },
                async single() {
                    return { data: { id: userId }, error: null };
                },
            };
        },
    };

    assert.equal(await resolveOAuthUser(supabase, 'google', rawSubject), userId);
    assert.deepEqual(storedUser, {
        oauth_provider: 'google',
        oauth_subject_hash: expectedHash,
    });
    assert.equal(JSON.stringify(storedUser).includes(rawSubject), false);
});

test('validates Wallet badges without accepting personal document fields', () => {
    const result = validateWalletSavePayload({
        verified: true,
        isAdult: true,
        documentType: 'passport',
        issuingCountry: 'DEU',
        expiresAt: '2099-12-31',
    }, countryCodes, Date.parse('2026-01-01T00:00:00Z'));
    assert.deepEqual(result, {
        ok: true,
        credential: {
            verified: true,
            isAdult: true,
            documentType: 'passport',
            issuingCountry: 'DEU',
            expiresAt: '2099-12-31T23:59:59.999Z',
        },
    });

    for (const field of ['fullName', 'documentNumber', 'dateOfBirth', 'mrz', 'photo']) {
        assert.equal(validateWalletSavePayload({
            verified: true,
            isAdult: true,
            documentType: 'passport',
            issuingCountry: 'DEU',
            expiresAt: '2099-12-31',
            [field]: 'must-not-be-saved',
        }, countryCodes).ok, false, `${field} must not be accepted`);
    }
});

test('rejects expired documents and invalid country or date values', () => {
    const valid = {
        verified: true,
        isAdult: true,
        documentType: 'id-card',
        issuingCountry: 'GBR',
        expiresAt: '2025-01-01',
    };
    assert.equal(validateWalletSavePayload(
        valid,
        countryCodes,
        Date.parse('2025-01-02T00:00:00Z')
    ).error, 'expired-document');
    assert.equal(validateWalletSavePayload(
        { ...valid, issuingCountry: 'UTO' },
        countryCodes
    ).error, 'invalid-wallet-credential');
    assert.equal(validateWalletSavePayload(
        { ...valid, expiresAt: '2099-02-31' },
        countryCodes
    ).error, 'expired-document');
});

test('persists and approves only current adult Wallet badges without PII', () => {
    const credential = {
        verified: true,
        isAdult: true,
        documentType: 'passport',
        issuingCountry: 'USA',
        expiresAt: '2099-12-31T23:59:59.999Z',
    };
    const record = createWalletCredentialRecord(
        userId,
        credential,
        '2026-01-01T00:00:00.000Z'
    );
    assert.deepEqual(Object.keys(record).sort(), [
        'document_type',
        'expires_at',
        'is_adult',
        'issuing_country',
        'user_id',
        'verified',
        'verified_at',
    ]);

    const wallet = formatWalletCredential({
        verified: true,
        is_adult: true,
        document_type: 'passport',
        issuing_country: 'USA',
        verified_at: '2026-01-01T00:00:00.000Z',
        expires_at: '2099-12-31T23:59:59.999Z',
    }, Date.parse('2026-01-02T00:00:00Z'));
    assert.equal(wallet.isEligibleForAgeGate, true);
    assert.deepEqual(getWalletVerificationOutcome({
        verified: true,
        is_adult: true,
        document_type: 'passport',
        issuing_country: 'USA',
        expires_at: '2099-12-31T23:59:59.999Z',
    }, Date.parse('2026-01-02T00:00:00Z')), {
        verified: true,
        documentType: 'passport',
        issuingCountry: 'USA',
        isAdult: true,
    });

    const underage = {
        verified: true,
        is_adult: false,
        document_type: 'id-card',
        issuing_country: 'GBR',
        expires_at: '2099-12-31T23:59:59.999Z',
    };
    assert.equal(formatWalletCredential(underage).isEligibleForAgeGate, false);
    assert.equal(getWalletVerificationOutcome({
        ...underage,
        is_adult: true,
        expires_at: '2020-01-01T00:00:00.000Z',
    }), null);
});

test('Wallet-backed partner approval requires the account passkey and claims the QR once', () => {
    const now = Date.parse('2026-01-02T00:00:00Z');
    const wallet = {
        verified: true,
        is_adult: true,
        document_type: 'passport',
        issuing_country: 'DEU',
        expires_at: '2099-12-31T23:59:59.999Z',
    };
    const passkey = { user_id: userId, counter: 4 };
    const session = {
        userId,
        expiresAt: now + 60_000,
        verified: false,
        verificationTokenUsed: false,
        verificationPending: false,
    };
    const approval = validateWalletApproval(wallet, passkey, userId, now);
    assert.deepEqual(approval, {
        ok: true,
        outcome: {
            verified: true,
            documentType: 'passport',
            issuingCountry: 'DEU',
            isAdult: true,
        },
    });
    assert.equal(validateWalletApproval(wallet, { ...passkey, user_id: 'another-user' }, userId, now).error, 'passkey-not-found');
    assert.equal(validateWalletApproval({
        ...wallet,
        expires_at: '2020-01-01T00:00:00.000Z',
    }, passkey, userId, now).error, 'wallet-not-eligible');

    assert.equal(claimVerificationToken(session, now), null);
    const record = createVerificationRecord(
        approval.outcome,
        'hashed-single-use-qr-token',
        new Date(now).toISOString()
    );
    assert.equal(record.is_adult, true);
    assert.equal(record.session_token_hash, 'hashed-single-use-qr-token');
    assert.equal('document_number' in record, false);
    assert.equal(claimVerificationToken(session, now), 'used');
});
