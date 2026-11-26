export const PASSKEY_MODAL_DISMISSED_KEY = 'blindpass.passkey-modal-dismissed';

export function getEntryRoute(session) {
    return session?.loggedIn === true ? 'wallet' : 'entry';
}

export function getWalletRequestMode(wallet) {
    return wallet?.verified === true ? 'wallet' : 'scan';
}

export function getReturnActionLabel(verifierName) {
    const name = typeof verifierName === 'string' ? verifierName.trim() : '';
    return `Return to ${name || 'Verifier'}`;
}

export function buildVerificationReturnUrl(
    returnTo,
    appOrigin,
    { verifierToken, state, cancelled = false }
) {
    if (!returnTo) return null;
    const target = new URL(returnTo, appOrigin);
    target.searchParams.delete('verified');
    target.searchParams.delete('is_adult');
    target.searchParams.delete('is_over_18');
    target.searchParams.delete('verifier_token');
    target.searchParams.delete('state');
    target.searchParams.delete('cancelled');
    if (cancelled) {
        target.searchParams.set('cancelled', 'true');
    } else {
        if (typeof verifierToken !== 'string' || typeof state !== 'string') return null;
        target.searchParams.set('verifier_token', verifierToken);
        target.searchParams.set('state', state);
    }
    return target;
}

export function shouldShowPasskeyModal(hasPasskey, storage) {
    return !hasPasskey &&
        storage?.getItem(PASSKEY_MODAL_DISMISSED_KEY) !== 'dismissed';
}

export function dismissPasskeyModal(storage) {
    storage?.setItem(PASSKEY_MODAL_DISMISSED_KEY, 'dismissed');
}

export function getSessionTransition(session) {
    if (session?.cancelled) return 'cancelled';
    if (session?.verified) return 'verified';
    return 'pending';
}
