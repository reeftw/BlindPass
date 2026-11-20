import test from 'node:test';
import assert from 'node:assert/strict';
import {
    buildVerificationReturnUrl,
    dismissPasskeyModal,
    getEntryRoute,
    getReturnActionLabel,
    getSessionTransition,
    getWalletRequestMode,
    PASSKEY_MODAL_DISMISSED_KEY,
    shouldShowPasskeyModal,
} from '../public/verification-ui.js';

function createSessionStorage() {
    const values = new Map();
    return {
        getItem(key) { return values.get(key) || null; },
        setItem(key, value) { values.set(key, value); },
    };
}

test('a fresh verifier entry routes a signed-in account to Wallet instead of a stale QR view', () => {
    assert.equal(getEntryRoute({ loggedIn: true, sessionId: 'new-session' }), 'wallet');
    assert.equal(getEntryRoute({ loggedIn: false, sessionId: 'new-session' }), 'entry');
});

test('Wallet request shows phone scanning only when no verified ID is saved', () => {
    assert.equal(getWalletRequestMode({ verified: false }), 'scan');
    assert.equal(getWalletRequestMode(null), 'scan');
    assert.equal(getWalletRequestMode({ verified: true, isEligibleForAgeGate: true }), 'wallet');
    assert.equal(getWalletRequestMode({ verified: true, isEligibleForAgeGate: false }), 'wallet');
});

test('builds dynamic verifier return links with verification status parameters', () => {
    assert.equal(getReturnActionLabel('Discord'), 'Return to Discord');
    assert.equal(getReturnActionLabel(''), 'Return to Verifier');

    const returnUrl = buildVerificationReturnUrl(
        'https://discord.com/verify?source=blindpass',
        'https://blindpass.example',
        { verified: true, isAdult: true }
    );
    assert.equal(returnUrl.origin, 'https://discord.com');
    assert.equal(returnUrl.searchParams.get('source'), 'blindpass');
    assert.equal(returnUrl.searchParams.get('verified'), 'true');
    assert.equal(returnUrl.searchParams.get('is_adult'), 'true');

    const cancelledUrl = buildVerificationReturnUrl(
        'https://reddit.com/check',
        'https://blindpass.example',
        { verified: false, cancelled: true }
    );
    assert.equal(cancelledUrl.searchParams.get('verified'), 'false');
    assert.equal(cancelledUrl.searchParams.get('cancelled'), 'true');
    assert.equal(buildVerificationReturnUrl(null, 'https://blindpass.example', {
        verified: false,
        cancelled: true,
    }), null);
});

test('passkey prompt dismissal lasts only for the current session storage', () => {
    const currentSession = createSessionStorage();
    assert.equal(shouldShowPasskeyModal(false, currentSession), true);
    dismissPasskeyModal(currentSession);
    assert.equal(currentSession.getItem(PASSKEY_MODAL_DISMISSED_KEY), 'dismissed');
    assert.equal(shouldShowPasskeyModal(false, currentSession), false);
    assert.equal(shouldShowPasskeyModal(true, createSessionStorage()), false);
    assert.equal(shouldShowPasskeyModal(false, createSessionStorage()), true);
});

test('desktop polling distinguishes pending, verified, and cancelled sessions', () => {
    assert.equal(getSessionTransition({ verified: false, cancelled: false }), 'pending');
    assert.equal(getSessionTransition({ verified: true, cancelled: false }), 'verified');
    assert.equal(getSessionTransition({ verified: false, cancelled: true }), 'cancelled');
});
