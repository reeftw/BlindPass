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
    { verified, isAdult = false, cancelled = false }
) {
    if (!returnTo) return null;
    const target = new URL(returnTo, appOrigin);
    target.searchParams.set('verified', String(verified));
    if (cancelled) {
        target.searchParams.set('cancelled', 'true');
    } else {
        target.searchParams.set('is_adult', String(isAdult === true));
        target.searchParams.set('is_over_18', String(isAdult === true));
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
