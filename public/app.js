import { ICAO_COUNTRIES } from './icao-countries.js';
import { getCameraGuideCrop, getMrzCropRegion } from './camera-crop.js';
import { parseMrzText } from './mrz.js';
import {
    buildVerificationReturnUrl,
    dismissPasskeyModal,
    getEntryRoute,
    getReturnActionLabel,
    getSessionTransition,
    getWalletRequestMode,
    shouldShowPasskeyModal,
} from './verification-ui.js';

const scriptLoads = new Map();

const params = new URLSearchParams(window.location.search);
const sessionId = params.get('session');
const isPhoneFlow = params.get('mode') === 'phone';
const isMrzDebugMode = isPhoneFlow && params.get('debug') === '1';

let capturedBlob = null;
let capturedViewfinderCrop = null;
let cameraStream = null;
let verifierName = 'Verifier';
let desktopPollTimeout = null;
let phonePollTimeout = null;
let desktopPollingStopped = false;
let phonePollingStopped = false;
let desktopCompletionShown = false;
let pendingPhoneOutcome = null;
let isWalletScanMode = false;
let currentSession = null;
let accountHasPasskey = false;

function loadExternalScript(src, isReady) {
    if (isReady()) return Promise.resolve();
    if (scriptLoads.has(src)) return scriptLoads.get(src);

    const script = document.createElement('script');
    script.src = src;
    script.async = true;
    script.referrerPolicy = 'no-referrer';

    const loadPromise = new Promise((resolve, reject) => {
        script.addEventListener('load', () => resolve(), { once: true });
        script.addEventListener('error', () => {
            script.remove();
            scriptLoads.delete(src);
            const host = new URL(src, window.location.href).hostname;
            reject(new Error(`Could not load a required verification library (${host}).`));
        }, { once: true });
    });

    scriptLoads.set(src, loadPromise);
    document.head.appendChild(script);
    return loadPromise;
}

async function getTesseract() {
    await loadExternalScript(
        '/vendor/tesseract/tesseract.min.js',
        () => Boolean(window.Tesseract)
    );
    if (!window.Tesseract) throw new Error('The local OCR library did not initialize.');
    return window.Tesseract;
}

async function getPasskeyBrowser() {
    await loadExternalScript(
        '/vendor/simplewebauthn/index.umd.min.js',
        () => Boolean(window.SimpleWebAuthnBrowser)
    );
    const passkeyBrowser = window.SimpleWebAuthnBrowser;
    if (
        !passkeyBrowser ||
        typeof passkeyBrowser.startRegistration !== 'function' ||
        typeof passkeyBrowser.startAuthentication !== 'function'
    ) {
        throw new Error('The passkey library did not initialize.');
    }
    return passkeyBrowser;
}

async function passkeyRequest(endpoint, payload) {
    const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        cache: 'no-store',
        body: JSON.stringify(payload),
    });
    let result = null;
    try {
        result = await response.json();
    } catch {
        // Use the status-based message below when the response isn't JSON.
    }
    if (!response.ok) {
        const error = new Error(
            result?.error || `Passkey verification failed (${response.status}).`
        );
        error.code = result?.code;
        throw error;
    }
    return result;
}

async function registerPasskey(qrToken = null) {
    const passkeyBrowser = await getPasskeyBrowser();
    const body = qrToken ? { qrToken } : {};
    const { flowToken, options } = await passkeyRequest(
        '/api/passkey/register/options',
        body
    );
    const response = await passkeyBrowser.startRegistration({ optionsJSON: options });
    await passkeyRequest('/api/passkey/register/verify', {
        ...body,
        flowToken,
        response,
    });
}

async function approveWalletForSession(qrToken) {
    const passkeyBrowser = await getPasskeyBrowser();
    const { flowToken, options } = await passkeyRequest(
        '/api/verify/wallet/options',
        { qrToken }
    );
    const assertion = await passkeyBrowser.startAuthentication({ optionsJSON: options });
    await passkeyRequest('/api/verify/wallet', {
        qrToken,
        flowToken,
        assertion,
    });
}

function renderWallet(wallet, badgeElement, detailsElement) {
    if (!badgeElement || !detailsElement) return;
    if (!wallet?.verified) {
        badgeElement.innerText = 'No verified ID in your BlindPass Wallet yet.';
        detailsElement.innerText = 'Scan a passport or ID card to create your private age-verification badge.';
        return;
    }

    if (wallet.isAdult && wallet.isCurrent) {
        badgeElement.innerText = 'Age Verified (18+)';
    } else if (wallet.isAdult) {
        badgeElement.innerText = 'Wallet credential expired';
    } else {
        badgeElement.innerText = 'ID checked; under 18';
    }
    const documentLabel = wallet.documentType === 'id-card' ? 'ID Card' : 'Passport';
    const expiry = wallet.expiresAt
        ? new Date(wallet.expiresAt).toLocaleDateString()
        : 'not available';
    detailsElement.innerText = `${documentLabel} · ${wallet.issuingCountry || 'Unknown issuer'} · Expires ${expiry}`;
}

async function registerPasskeyFromButton(button, messageElement, qrToken = null) {
    if (button) button.disabled = true;
    try {
        await registerPasskey(qrToken);
        if (messageElement) messageElement.innerText = 'Passkey saved. Use it for sign-in and secure age verification.';
        accountHasPasskey = true;
        if (currentSession) currentSession.hasPasskey = true;
        document.getElementById('profilePasskeyBtn')?.classList.add('hidden');
        document.getElementById('passkeyModalBackdrop')?.classList.add('hidden');
        return true;
    } finally {
        if (button) button.disabled = false;
    }
}

async function signInWithPasskey() {
    const button = document.getElementById('passkeyLoginBtn');
    if (button) button.disabled = true;
    try {
        const body = sessionId ? { qrToken: sessionId } : {};
        const { flowToken, options } = await passkeyRequest(
            '/api/passkey/login/options',
            body
        );
        const passkeyBrowser = await getPasskeyBrowser();
        const assertion = await passkeyBrowser.startAuthentication({ optionsJSON: options });
        await passkeyRequest('/api/passkey/login/verify', {
            ...body,
            flowToken,
            assertion,
        });
        window.location.reload();
    } catch (error) {
        console.error('Passkey sign-in failed:', error);
    } finally {
        if (button) button.disabled = false;
    }
}

async function saveWalletBadge(outcome, qrToken = null) {
    const requestBody = qrToken ? { qrToken } : {};
    const { flowToken, options } = await passkeyRequest(
        '/api/wallet/save/options',
        requestBody
    );
    const assertion = await (await getPasskeyBrowser()).startAuthentication({
        optionsJSON: options,
    });
    return passkeyRequest('/api/wallet/save', {
        ...requestBody,
        verified: true,
        isAdult: outcome.isAdult,
        documentType: outcome.documentType,
        issuingCountry: outcome.issuingCountry,
        expiresAt: outcome.expiresAt,
        flowToken,
        assertion,
    });
}

async function confirmPhonePasskey() {
    const statusDiv = document.getElementById('status');
    const confirmButton = document.getElementById('confirmPasskeyBtn');
    if (!pendingPhoneOutcome || !statusDiv || !confirmButton) return;

    confirmButton.disabled = true;
    statusDiv.innerText = 'Confirm the ID verification with your passkey...';
    try {
        let challenge;
        try {
            challenge = await passkeyRequest('/api/verify/scanned-id/options', {
                qrToken: sessionId,
            });
        } catch (error) {
            if (error.code !== 'passkey-not-found') throw error;
            statusDiv.innerText = 'Save a passkey to finish verifying your ID.';
            await registerPasskey(sessionId);
            accountHasPasskey = true;
            if (currentSession) currentSession.hasPasskey = true;
            document.getElementById('profilePasskeyBtn')?.classList.add('hidden');
            closePasskeyModal(false);
            confirmButton.innerText = 'Complete verification';
            statusDiv.innerText = 'Passkey saved. Tap Complete verification to finish.';
            return;
        }

        const passkeyBrowser = await getPasskeyBrowser();
        const assertion = await passkeyBrowser.startAuthentication({
            optionsJSON: challenge.options,
        });
        const result = await passkeyRequest('/api/verify/scanned-id', {
            qrToken: sessionId,
            flowToken: challenge.flowToken,
            assertion,
            verified: true,
            isAdult: pendingPhoneOutcome.isAdult,
            documentType: pendingPhoneOutcome.documentType,
            issuingCountry: pendingPhoneOutcome.issuingCountry,
            expiresAt: pendingPhoneOutcome.expiresAt,
        });

        pendingPhoneOutcome = null;
        document.getElementById('phoneControls')?.classList.add('hidden');
        showPhoneCompletion(result.isAdult);
    } catch (error) {
        console.error('Wallet verification failed:', error);
        const message = error instanceof Error ? error.message : 'Unexpected processing error.';
        statusDiv.innerText = `Wallet verification failed: ${message}`;
    } finally {
        confirmButton.disabled = false;
    }
}

async function verifyWalletFromRequest() {
    const status = document.getElementById('walletVerifyHint');
    const button = document.getElementById('walletVerifyBtn');
    if (!sessionId || !button) return;
    button.disabled = true;
    if (status) status.innerText = 'Confirm with your passkey to verify from Wallet.';
    try {
        await approveWalletForSession(sessionId);
        const response = await fetch(`/api/session/${encodeURIComponent(sessionId)}`, {
            cache: 'no-store',
        });
        if (!response.ok) throw new Error(`Could not load verification status (${response.status}).`);
        showDesktopCompletion(await response.json());
    } catch (error) {
        console.error('Wallet approval failed:', error);
        if (status) {
            status.innerText = error instanceof Error
                ? `Wallet verification failed: ${error.message}`
                : 'Wallet verification failed. Try again.';
        }
    } finally {
        button.disabled = false;
    }
}

function initializeMrzDebugPanel() {
    if (!isMrzDebugMode) return;
    document.getElementById('mrzDebugPanel')?.classList.remove('hidden');
    const output = document.getElementById('mrzDebugOutput');
    if (output) output.textContent = 'OCR output will appear here after you select Verify ID.';
}

function clearMrzDebugOutput() {
    const output = document.getElementById('mrzDebugOutput');
    if (output) output.textContent = '';
}

function appendMrzDebugOutput(stage, text) {
    if (!isMrzDebugMode) return;
    const panel = document.getElementById('mrzDebugPanel');
    const output = document.getElementById('mrzDebugOutput');
    if (!panel || !output) return;

    panel.classList.remove('hidden');
    const existingText = output.textContent;
    const prefix = existingText && !existingText.startsWith('OCR output will')
        ? `${existingText}\n\n`
        : '';
    output.textContent = `${prefix}${stage}\n${text || '[No text recognized]'}`;
}

function populateDocumentCountries() {
    const countrySelect = document.getElementById('documentCountry');
    if (!countrySelect) return;

    const options = document.createDocumentFragment();
    for (const [name, code] of ICAO_COUNTRIES) {
        const option = document.createElement('option');
        option.value = code;
        if (code === 'DEU') option.innerText = `${name} (DEU or D<<)`;
        else if (code === 'GBR') option.innerText = `${name} (GBR, GBD, GBN, GBO, GBP, GBS)`;
        else option.innerText = `${name} (${code})`;
        options.appendChild(option);
    }
    countrySelect.appendChild(options);
}

function updateDocumentFraming() {
    const documentType = document.getElementById('documentType')?.value;
    const viewfinder = document.getElementById('cameraViewfinder');
    const hint = document.getElementById('viewfinderHint');
    const isIdCard = documentType === 'id-card';

    viewfinder?.classList.toggle('id-card-framing', isIdCard);
    if (hint) {
        hint.innerText = isIdCard
            ? 'Place the back of the ID card in the outline, with all three MRZ lines visible.'
            : 'Place the passport page flat and well-lit inside the outline, with both MRZ lines visible.';
    }
}

async function loadAccountDashboard() {
    const loginCard = document.getElementById('loginCard');
    const accountCard = document.getElementById('accountCard');
    const sessionBanner = document.getElementById('sessionBanner');
    try {
        const response = await fetch('/api/account', { cache: 'no-store' });
        if (response.status === 401) {
            loginCard?.classList.remove('hidden');
            accountCard?.classList.add('hidden');
            return null;
        }
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || `Account request failed (${response.status}).`);

        loginCard?.classList.add('hidden');
        accountCard?.classList.remove('hidden');
        const identity = document.getElementById('accountIdentity');
        if (identity) identity.innerText = `Signed in with ${result.provider.toUpperCase()}`;
        renderWallet(
            result.wallet,
            document.getElementById('accountWalletBadge'),
            document.getElementById('accountWalletDetails')
        );
        updateProfile(result);
        maybeShowPasskeyModal(result.hasPasskey);
        return result;
    } catch (error) {
        console.error('Could not load the BlindPass account:', error);
        if (sessionBanner) {
            sessionBanner.innerText = error instanceof Error
                ? `Could not load your account: ${error.message}`
                : 'Could not load your BlindPass account.';
        }
        return null;
    }
}

function updateProfile(account) {
    const profileMenu = document.getElementById('profileMenu');
    const provider = document.getElementById('profileProvider');
    const identifier = document.getElementById('profileAccountId');
    accountHasPasskey = account?.hasPasskey === true;
    if (!account?.loggedIn && !account?.provider) {
        profileMenu?.classList.add('hidden');
        return;
    }

    profileMenu?.classList.remove('hidden');
    if (provider) {
        provider.innerText = `${account.provider.toUpperCase()} account`;
    }
    if (identifier) {
        identifier.innerText = `Account ID · ${account.accountLabel || 'private'}`;
    }
    renderWallet(
        account.wallet,
        document.getElementById('profileWalletBadge'),
        document.getElementById('profileWalletDetails')
    );
    document.getElementById('profileScanBtn')
        ?.classList.toggle('hidden', Boolean(sessionId && currentSession?.verified));
    document.getElementById('profilePasskeyBtn')
        ?.classList.toggle('hidden', accountHasPasskey);
}

function maybeShowPasskeyModal(hasPasskey) {
    if (!shouldShowPasskeyModal(hasPasskey, window.sessionStorage)) return;
    document.getElementById('passkeyModalBackdrop')?.classList.remove('hidden');
    document.getElementById('passkeyModalSaveBtn')?.focus();
}

function closePasskeyModal(dismiss = false) {
    if (dismiss) dismissPasskeyModal(window.sessionStorage);
    document.getElementById('passkeyModalBackdrop')?.classList.add('hidden');
}

function showProfilePopover(show) {
    const button = document.getElementById('profileAvatarBtn');
    const popover = document.getElementById('profilePopover');
    if (!button || !popover) return;
    const isOpen = show ?? popover.classList.contains('hidden');
    popover.classList.toggle('hidden', !isOpen);
    button.setAttribute('aria-expanded', String(isOpen));
}

async function startWalletScan() {
    showProfilePopover(false);
    if (isPhoneFlow && sessionId) {
        document.getElementById('phoneControls')?.classList.remove('hidden');
        document.getElementById('documentScanControls')?.classList.remove('hidden');
        await openIdCamera();
        return;
    }
    if (sessionId) {
        showPhoneQrForSession();
        return;
    }

    isWalletScanMode = true;
    document.body.classList.add('phone-flow');
    document.getElementById('accountCard')?.classList.add('hidden');
    document.getElementById('walletRequestCard')?.classList.add('hidden');
    document.getElementById('loginCard')?.classList.add('hidden');
    document.getElementById('verifyCard')?.classList.add('hidden');
    document.getElementById('phoneCard')?.classList.remove('hidden');
    document.getElementById('phoneControls')?.classList.remove('hidden');
    document.getElementById('documentScanControls')?.classList.remove('hidden');
    const status = document.getElementById('status');
    if (status) {
        status.classList.remove('hidden');
        status.classList.add('status-text');
        status.innerText = 'Select your document type and issuing country, then scan your ID.';
    }
}

function setDocumentOptionsDisabled(disabled) {
    for (const id of ['documentCountry', 'documentType']) {
        const control = document.getElementById(id);
        if (control) control.disabled = disabled;
    }
}

function showPhoneQrForSession() {
    const walletCard = document.getElementById('walletRequestCard');
    const verifyCard = document.getElementById('verifyCard');
    if (!currentSession?.phoneReady) {
        const status = document.getElementById('walletVerifyHint');
        if (status) status.innerText = 'Phone ID scanning requires an HTTPS BlindPass link.';
        return;
    }
    walletCard?.classList.add('hidden');
    verifyCard?.classList.remove('hidden');
    document.getElementById('qrUnavailable')?.classList.add('hidden');
    document.getElementById('qrLayout')?.classList.remove('hidden');
    document.getElementById('qrExpiry')?.classList.remove('hidden');
    const qrImage = document.getElementById('phoneQrCode');
    if (qrImage && sessionId) {
        qrImage.src = `/api/session/${encodeURIComponent(sessionId)}/qr`;
    }
    document.getElementById('cancelVerificationBtn')?.classList.remove('hidden');
    const desktopStatus = document.getElementById('desktopStatus');
    if (desktopStatus) {
        desktopStatus.innerText = `Scan this one-time code with your phone to verify for ${verifierName || 'Verifier'}.`;
    }
    startDesktopPolling();
}

function showWalletRequest(session) {
    const loginCard = document.getElementById('loginCard');
    const accountCard = document.getElementById('accountCard');
    const requestCard = document.getElementById('walletRequestCard');
    const verifyCard = document.getElementById('verifyCard');
    const wallet = session.wallet;
    loginCard?.classList.add('hidden');
    accountCard?.classList.add('hidden');
    verifyCard?.classList.add('hidden');
    requestCard?.classList.remove('hidden');

    const requestedBy = document.getElementById('requestVerifierName');
    if (requestedBy) requestedBy.innerText = verifierName || 'Verifier';
    renderWallet(
        wallet,
        document.getElementById('requestWalletBadge'),
        document.getElementById('requestWalletDetails')
    );
    const hasVerifiedWallet = getWalletRequestMode(wallet) === 'wallet';
    const eligible = wallet?.isEligibleForAgeGate === true;
    const hasPasskey = session.hasPasskey === true;
    const verifyButton = document.getElementById('walletVerifyBtn');
    const scanButton = document.getElementById('walletScanPhoneBtn');
    const hint = document.getElementById('walletVerifyHint');
    if (verifyButton) {
        verifyButton.innerText = `Verify ${verifierName || 'Verifier'} with BlindPass Wallet`;
        verifyButton.classList.toggle('hidden', !hasVerifiedWallet);
        verifyButton.disabled = !eligible || !hasPasskey;
    }
    if (scanButton) {
        scanButton.classList.toggle('hidden', hasVerifiedWallet);
        scanButton.disabled = !session.phoneReady;
    }
    if (hint) {
        if (!wallet?.verified) {
            hint.innerText = 'Your Wallet does not have a verified ID yet. Continue on your phone to scan one.';
        } else if (!eligible) {
            hint.innerText = 'Your Wallet ID is expired or is not eligible for an 18+ request. Use Scan / Refresh ID from the Profile menu.';
        } else if (!hasPasskey) {
            hint.innerText = 'Save a passkey from the Profile menu to verify from your Wallet.';
        } else {
            hint.innerText = 'Your ID image and personal details are never shared with the requesting site.';
        }
    }
    updateProfile({
        loggedIn: true,
        provider: session.provider,
        accountLabel: session.accountLabel,
        hasPasskey,
        wallet,
    });
    maybeShowPasskeyModal(hasPasskey);
}

async function initBlindPassSession() {
    const sessionBanner = document.getElementById('sessionBanner');
    const loginCard = document.getElementById('loginCard');
    const verifyCard = document.getElementById('verifyCard');
    const phoneCard = document.getElementById('phoneCard');
    const loggedInUser = document.getElementById('loggedInUser');
    const phoneAccount = document.getElementById('phoneAccount');
    const phoneStatus = document.getElementById('status');
    const googleLink = document.getElementById('googleLoginLink');
    const msLink = document.getElementById('msLoginLink');
    const phoneControls = document.getElementById('phoneControls');

    if (isPhoneFlow) {
        document.body.classList.add('phone-flow');
        loginCard?.classList.add('hidden');
        verifyCard?.classList.add('hidden');
        phoneCard?.classList.remove('hidden');
    }

    if (!sessionId) {
        if (isPhoneFlow && phoneStatus) {
            phoneStatus.innerText = 'This phone link is incomplete. Return to the requesting site and scan its QR code again.';
            return;
        }
        if (sessionBanner) sessionBanner.innerText = 'Manage your private BlindPass age-verification Wallet.';
        await loadAccountDashboard();
        return;
    }

    if (googleLink) googleLink.href = `/auth/google?session=${encodeURIComponent(sessionId)}`;
    if (msLink) msLink.href = `/auth/microsoft?session=${encodeURIComponent(sessionId)}`;

    try {
        const res = await fetch(`/api/session/${encodeURIComponent(sessionId)}`, { cache: 'no-store' });
        if (!res.ok) {
            const message = 'This verification link is invalid or expired. Return to the requesting site and start again.';
            if (isPhoneFlow && phoneStatus) phoneStatus.innerText = message;
            else if (sessionBanner) sessionBanner.innerText = message;
            return;
        }
        let session = await res.json();
        if (!isPhoneFlow && !session.loggedIn) {
            const claimResponse = await fetch(
                `/api/session/${encodeURIComponent(sessionId)}/claim`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    cache: 'no-store',
                    body: '{}',
                }
            );
            if (claimResponse.ok) {
                const refreshedSession = await fetch(
                    `/api/session/${encodeURIComponent(sessionId)}`,
                    { cache: 'no-store' }
                );
                if (!refreshedSession.ok) {
                    throw new Error(`Could not load claimed session (${refreshedSession.status}).`);
                }
                session = await refreshedSession.json();
            } else if (claimResponse.status !== 401) {
                throw new Error(`Could not claim verification session (${claimResponse.status}).`);
            }
        }
        currentSession = session;
        verifierName = session.verifierName || session.verifier || 'Verifier';

        if (isPhoneFlow) {
            if (!session.loggedIn) {
                if (phoneStatus) phoneStatus.innerText = 'Return to your computer, sign in, then scan the new QR code.';
                return;
            }
            if (phoneAccount) {
                phoneAccount.innerText = `Requested by ${verifierName || 'Verifier'} · signed in with ${session.provider.toUpperCase()}`;
            }
            if (session.cancelled) {
                redirectFromCancelledSession(session);
                return;
            }
            if (session.verified) {
                phoneControls?.classList.add('hidden');
                showPhoneCompletion(session.isOver18);
                return;
            }
            if (session.appOrigin !== window.location.origin || !session.phoneReady) {
                if (phoneStatus) {
                    phoneStatus.innerText = 'Open this link from the configured HTTPS site to use the phone camera.';
                }
                return;
            }
            phoneControls?.classList.remove('hidden');
            if (phoneStatus) {
                phoneStatus.innerText = "Your ID image stays on this device. Select Open camera when you're ready.";
                phoneStatus.classList.add('status-text');
            }
            updateProfile({
                loggedIn: true,
                provider: session.provider,
                accountLabel: session.accountLabel,
                hasPasskey: session.hasPasskey,
                wallet: session.wallet,
            });
            maybeShowPasskeyModal(session.hasPasskey);
            startPhoneSessionPolling();
            return;
        }

        if (sessionBanner) {
            sessionBanner.innerText = `Requested by: ${verifierName}`;
        }

        if (getEntryRoute(session) === 'wallet') {
            if (session.cancelled) {
                redirectFromCancelledSession(session);
                return;
            }
            if (session.verified) {
                showDesktopCompletion(session);
                return;
            }
            showWalletRequest(session);
            if (loggedInUser) {
                loggedInUser.innerText = `Signed in with ${session.provider.toUpperCase()}`;
            }
        } else {
            loginCard?.classList.remove('hidden');
            document.getElementById('accountCard')?.classList.add('hidden');
            document.getElementById('walletRequestCard')?.classList.add('hidden');
            document.getElementById('verifyCard')?.classList.add('hidden');
            updateProfile(null);
        }
    } catch (err) {
        console.error('Session load error:', err);
        const message = 'Could not load this verification session. Check your connection and try again.';
        if (isPhoneFlow && phoneStatus) phoneStatus.innerText = message;
        else if (sessionBanner) sessionBanner.innerText = message;
    }
}

function showQrUnavailable(message) {
    const qrLayout = document.getElementById('qrLayout');
    const qrUnavailable = document.getElementById('qrUnavailable');
    const qrExpiry = document.getElementById('qrExpiry');
    qrLayout?.classList.add('hidden');
    qrExpiry?.classList.add('hidden');
    const qrImage = document.getElementById('phoneQrCode');
    if (qrImage) qrImage.removeAttribute('src');
    if (qrUnavailable) {
        qrUnavailable.innerText = message;
        qrUnavailable.classList.remove('hidden');
    }
}

function redirectFromCancelledSession(session = currentSession) {
    desktopPollingStopped = true;
    phonePollingStopped = true;
    if (desktopPollTimeout) window.clearTimeout(desktopPollTimeout);
    if (phonePollTimeout) window.clearTimeout(phonePollTimeout);
    const target = buildVerificationReturnUrl(
        session?.returnTo,
        session?.appOrigin || window.location.origin,
        { verified: false, cancelled: true }
    );
    if (target) {
        window.location.assign(target.toString());
    } else {
        window.history.back();
    }
}

async function showDesktopCompletion(session) {
    if (desktopCompletionShown) return;
    desktopCompletionShown = true;
    desktopPollingStopped = true;
    if (desktopPollTimeout) window.clearTimeout(desktopPollTimeout);

    const desktopResult = document.getElementById('desktopResult');
    const desktopReturnBtn = document.getElementById('desktopReturnBtn');
    currentSession = session;
    let target = null;
    let returnTokenError = false;
    try {
        target = await getRequesterReturnUrl(session);
    } catch (error) {
        console.error('Could not prepare verifier return token:', error);
        returnTokenError = true;
    }
    if (desktopResult) {
        desktopResult.innerText = returnTokenError
            ? 'ID verified, but a secure verifier result could not be prepared.'
            : session.isOver18
                ? 'ID Verified (18+).'
                : 'ID Verified — Under 18.';
    }
    if (desktopReturnBtn) {
        desktopReturnBtn.href = target?.toString() || '#';
        desktopReturnBtn.innerText = getReturnActionLabel(
            session.verifierName || session.verifier || verifierName
        );
        desktopReturnBtn.dataset.returnUrl = target?.toString() || '';
    }

    document.getElementById('loginCard')?.classList.add('hidden');
    document.getElementById('accountCard')?.classList.add('hidden');
    document.getElementById('walletRequestCard')?.classList.add('hidden');
    document.getElementById('verifyCard')?.classList.remove('hidden');
    document.getElementById('qrLayout')?.classList.add('hidden');
    document.getElementById('qrExpiry')?.classList.add('hidden');
    document.getElementById('qrUnavailable')?.classList.add('hidden');
    document.getElementById('cancelVerificationBtn')?.classList.add('hidden');
    document.getElementById('desktopDone')?.classList.remove('hidden');
    document.getElementById('profileScanBtn')?.classList.toggle('hidden', Boolean(sessionId));
    closePasskeyModal(false);
    showProfilePopover(false);
}

async function getRequesterReturnUrl(session) {
    if (!session.returnTo || !sessionId) return null;
    const response = await fetch(
        `/api/session/${encodeURIComponent(sessionId)}/return-token`,
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            cache: 'no-store',
            body: '{}',
        }
    );
    const result = await response.json();
    if (!response.ok) {
        throw new Error(result.error || 'Could not prepare a secure verifier result.');
    }
    return buildVerificationReturnUrl(
        session.returnTo,
        session.appOrigin || window.location.origin,
        { verifierToken: result.token, state: result.state }
    );
}

function showPhoneCompletion(isAdult = true) {
    phonePollingStopped = true;
    if (phonePollTimeout) window.clearTimeout(phonePollTimeout);
    document.getElementById('status')?.classList.add('hidden');
    document.getElementById('phoneControls')?.classList.add('hidden');
    const title = document.getElementById('phoneDoneTitle');
    const result = document.getElementById('phoneResult');
    if (title) title.innerText = isAdult ? 'ID Verified (18+)' : 'ID Verified — Under 18';
    if (result) {
        result.innerText = `Your age verification for ${verifierName || 'Verifier'} is complete. You can now return to your PC.`;
    }
    document.getElementById('phoneDone')?.classList.remove('hidden');
    document.getElementById('mrzDebugPanel')?.classList.add('hidden');
    document.getElementById('profileScanBtn')?.classList.toggle('hidden', Boolean(sessionId));
    closePasskeyModal(false);
    showProfilePopover(false);
}

function startDesktopPolling() {
    desktopPollingStopped = false;
    pollDesktopVerification();
}

async function pollDesktopVerification() {
    if (desktopPollingStopped || desktopCompletionShown) return;

    try {
        const res = await fetch(`/api/session/${encodeURIComponent(sessionId)}`, { cache: 'no-store' });
        if (res.status === 404) {
            desktopPollingStopped = true;
            showQrUnavailable('This verification session has expired. Start again from the requesting site.');
            return;
        }
        if (!res.ok) {
            throw new Error(`Session status request failed (${res.status})`);
        }

        const session = await res.json();
        currentSession = session;
        if (getSessionTransition(session) === 'cancelled') {
            redirectFromCancelledSession(session);
            return;
        }
        if (getSessionTransition(session) === 'verified') {
            showDesktopCompletion(session);
            return;
        }
    } catch (err) {
        console.error('Verification status check failed:', err);
        const desktopStatus = document.getElementById('desktopStatus');
        if (desktopStatus) desktopStatus.innerText = 'Connection interrupted. Checking again...';
    } finally {
        if (!desktopPollingStopped && !desktopCompletionShown) {
            desktopPollTimeout = window.setTimeout(pollDesktopVerification, 2000);
        }
    }
}

async function pollPhoneSession() {
    if (phonePollingStopped || !isPhoneFlow || !sessionId || phonePollTimeout) return;
    try {
        const response = await fetch(`/api/session/${encodeURIComponent(sessionId)}`, {
            cache: 'no-store',
        });
        if (response.status === 404) return;
        if (!response.ok) throw new Error(`Phone session status request failed (${response.status})`);
        const session = await response.json();
        currentSession = session;
        if (getSessionTransition(session) === 'cancelled') {
            redirectFromCancelledSession(session);
            return;
        }
        if (getSessionTransition(session) === 'verified') {
            showPhoneCompletion(session.isOver18);
            return;
        }
    } catch (error) {
        console.error('Phone verification status check failed:', error);
    } finally {
        if (isPhoneFlow && !document.getElementById('phoneDone')?.classList.contains('hidden')) {
            phonePollTimeout = null;
        } else if (isPhoneFlow && !phonePollingStopped) {
            phonePollTimeout = window.setTimeout(() => {
                phonePollTimeout = null;
                pollPhoneSession();
            }, 2000);
        }
    }
}

function startPhoneSessionPolling() {
    if (phonePollTimeout) window.clearTimeout(phonePollTimeout);
    phonePollTimeout = null;
    phonePollingStopped = false;
    pollPhoneSession();
}

async function cancelDesktopVerification(button = document.getElementById('cancelVerificationBtn')) {
    const cancelButton = button;
    const desktopStatus = document.getElementById('desktopStatus');
    if (!sessionId || cancelButton?.disabled || desktopCompletionShown) return;

    if (cancelButton) {
        cancelButton.disabled = true;
        cancelButton.innerText = 'Cancelling...';
    }
    if (desktopStatus) desktopStatus.innerText = 'Cancelling verification...';

    try {
        const response = await fetch(
            `/api/session/${encodeURIComponent(sessionId)}/cancel`,
            { method: 'POST' }
        );
        if (!response.ok) {
            let errorMessage = `Could not cancel verification (${response.status}).`;
            try {
                const result = await response.json();
                if (result.error) errorMessage = result.error;
            } catch {
                // Keep the explicit status-based message if the response isn't JSON.
            }
            throw new Error(errorMessage);
        }

        const result = await response.json();
        redirectFromCancelledSession({
            ...currentSession,
            returnTo: result.returnTo || currentSession?.returnTo,
        });
    } catch (error) {
        console.error('Could not cancel verification:', error);
        const message = error instanceof Error ? error.message : 'Unexpected cancellation error.';
        if (desktopStatus) desktopStatus.innerText = message;
    } finally {
        if (!desktopPollingStopped && cancelButton) {
            cancelButton.disabled = false;
            cancelButton.innerText = 'Cancel and return';
        }
    }
}

async function saveProfilePasskey(button) {
    if (!button || button.disabled) return;
    const feedback = document.getElementById('profileFeedback');
    const modalCopy = document.getElementById('passkeyModalCopy');
    const messageElement = button.id === 'passkeyModalSaveBtn' ? modalCopy : feedback;
    try {
        await registerPasskeyFromButton(button, messageElement, sessionId || null);
        if (currentSession) {
            currentSession.hasPasskey = true;
            accountHasPasskey = true;
            updateProfile({
                loggedIn: true,
                provider: currentSession.provider,
                accountLabel: currentSession.accountLabel,
                hasPasskey: true,
                wallet: currentSession.wallet,
            });
            const canUseWallet = currentSession.wallet?.isEligibleForAgeGate === true;
            const walletButton = document.getElementById('walletVerifyBtn');
            if (walletButton) walletButton.disabled = !canUseWallet;
            const hint = document.getElementById('walletVerifyHint');
            if (hint && canUseWallet) {
                hint.innerText = 'Your ID image and personal details are never shared with the requesting site.';
            }
        } else {
            await loadAccountDashboard();
        }
    } catch (error) {
        console.error('Could not save passkey:', error);
        const message = error instanceof Error ? error.message : 'Could not save your passkey.';
        if (messageElement) messageElement.innerText = `Could not save passkey: ${message}`;
        if (button.id === 'profilePasskeyBtn') {
            button.innerText = `Could not save passkey: ${message}`;
        }
    }
}

async function signOut() {
    const button = document.getElementById('profileSignOutBtn');
    if (button) button.disabled = true;
    try {
        const response = await fetch('/api/auth/logout', { method: 'POST' });
        if (!response.ok) throw new Error(`Sign out failed (${response.status}).`);
        window.location.assign('/');
    } catch (error) {
        console.error('Could not sign out:', error);
        if (button) button.disabled = false;
        const feedback = document.getElementById('profileFeedback');
        if (feedback) {
            feedback.innerText = error instanceof Error ? error.message : 'Could not sign out.';
        }
    }
}

async function openIdCamera() {
    const video = document.getElementById('cameraVideo');
    const viewfinder = document.getElementById('cameraViewfinder');
    const snapBtn = document.getElementById('snapPhotoBtn');
    const statusDiv = document.getElementById('status');
    const openCamBtn = document.getElementById('openCamBtn');
    const captureMessage = document.getElementById('captureMessage');
    const verifyBtn = document.getElementById('verifyBtn');
    const countryCode = document.getElementById('documentCountry').value;

    if (!countryCode) {
        statusDiv.classList.remove('hidden');
        captureMessage.classList.add('hidden');
        statusDiv.innerText = 'Select the document type and issuing country before opening the camera.';
        return;
    }
    clearMrzDebugOutput();
    updateDocumentFraming();

    try {
        pendingPhoneOutcome = null;
        document.getElementById('confirmPasskeyBtn')?.classList.add('hidden');
        const isRetrying = Boolean(capturedBlob);
        captureMessage.classList.add('hidden');
        statusDiv.classList.remove('hidden');
        statusDiv.classList.remove('status-text');
        verifyBtn.classList.add('hidden');
        if (isRetrying) clearCapturedImage();
        if (isRetrying) openCamBtn.innerText = 'Retry';
        statusDiv.innerText = 'Opening camera...';
        if (!navigator.mediaDevices?.getUserMedia) {
            throw new Error('Camera access requires HTTPS on your phone');
        }
        cameraStream = await navigator.mediaDevices.getUserMedia({
            video: {
                facingMode: 'environment',
                width: { ideal: 1920 },
                height: { ideal: 1080 },
            },
        });
        video.srcObject = cameraStream;
        video.classList.remove('hidden');
        viewfinder.classList.remove('hidden');
        document.body.classList.add('camera-active');
        snapBtn.classList.remove('hidden');
        statusDiv.innerText = 'Camera ready. Center your ID and take a photo.';
    } catch (err) {
        const cameraError = err instanceof Error ? err : new Error('Unexpected camera error.');
        if (cameraError.name === 'NotAllowedError' || cameraError.name === 'PermissionDeniedError') {
            statusDiv.innerText = 'Camera access was denied. Allow camera access for this site in your browser settings, then tap Open camera.';
            statusDiv.classList.add('status-text');
        } else {
            statusDiv.innerText = `Camera unavailable: ${cameraError.message}. Open this link on your phone over HTTPS.`;
        }
    }
}

function captureIdPhoto() {
    const video = document.getElementById('cameraVideo');
    const guide = document.querySelector('.viewfinder-guide');
    const canvas = document.getElementById('photoCanvas');
    const preview = document.getElementById('photoPreview');
    const snapBtn = document.getElementById('snapPhotoBtn');
    const statusDiv = document.getElementById('status');
    const captureMessage = document.getElementById('captureMessage');

    if (!video || !video.videoWidth) {
        statusDiv.innerText = 'Wait for the camera preview, then take the photo again.';
        return;
    }

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const context = canvas.getContext('2d');
    if (!context) {
        statusDiv.innerText = 'Could not capture the camera image. Please try again.';
        return;
    }
    capturedViewfinderCrop = guide
        ? getCameraGuideCrop(
            video.getBoundingClientRect(),
            guide.getBoundingClientRect(),
            video.videoWidth,
            video.videoHeight
        )
        : null;
    context.drawImage(video, 0, 0);

    canvas.toBlob((blob) => {
        if (!blob) {
            statusDiv.innerText = 'Could not capture the camera image. Please try again.';
            return;
        }
        capturedBlob = blob;
        if (preview.src.startsWith('blob:')) URL.revokeObjectURL(preview.src);
        preview.src = URL.createObjectURL(blob);
        preview.classList.remove('hidden');
        captureMessage.innerText = 'Photo captured on this device. Select Verify ID to continue.';
        captureMessage.classList.remove('hidden');
        setDocumentOptionsDisabled(true);
        statusDiv.classList.add('hidden');
        document.getElementById('verifyBtn').classList.remove('hidden');
        document.getElementById('openCamBtn').innerText = 'Retry';
    }, 'image/jpeg', 0.92);

    stopCamera();
    video.classList.add('hidden');
    snapBtn.classList.add('hidden');
}

function stopCamera() {
    if (cameraStream) {
        cameraStream.getTracks().forEach((track) => track.stop());
        cameraStream = null;
    }
    const video = document.getElementById('cameraVideo');
    if (video) {
        video.pause();
        video.srcObject = null;
        video.classList.add('hidden');
    }
    document.getElementById('cameraViewfinder')?.classList.add('hidden');
    document.getElementById('snapPhotoBtn')?.classList.add('hidden');
    document.getElementById('verifyBtn')?.classList.add('hidden');
    document.body.classList.remove('camera-active');
}

function closeIdCamera() {
    stopCamera();
    document.getElementById('status').innerText = 'Camera is off. Allow access if prompted, then select Open camera to continue.';
}

function clearCapturedImage() {
    stopCamera();
    const preview = document.getElementById('photoPreview');
    if (preview) {
        if (preview.src.startsWith('blob:')) URL.revokeObjectURL(preview.src);
        preview.removeAttribute('src');
        preview.classList.add('hidden');
    }
    const canvas = document.getElementById('photoCanvas');
    if (canvas) {
        canvas.width = 0;
        canvas.height = 0;
    }
    setDocumentOptionsDisabled(false);
    capturedBlob = null;
    capturedViewfinderCrop = null;
}

async function createDocumentMrzCrop(blob, documentType, viewfinderCrop) {
    if (!viewfinderCrop || typeof createImageBitmap !== 'function') return null;
    const mrzCropRegion = getMrzCropRegion(viewfinderCrop, documentType);
    if (!mrzCropRegion) {
        throw new Error('Unsupported document type for MRZ cropping.');
    }

    const bitmap = await createImageBitmap(blob);
    try {
        const sourceLeft = Math.floor(bitmap.width * mrzCropRegion.left);
        const sourceTop = Math.floor(bitmap.height * mrzCropRegion.top);
        const sourceRight = Math.min(
            bitmap.width,
            Math.ceil(bitmap.width * (mrzCropRegion.left + mrzCropRegion.width))
        );
        const sourceBottom = Math.min(
            bitmap.height,
            Math.ceil(bitmap.height * (mrzCropRegion.top + mrzCropRegion.height))
        );
        const sourceWidth = sourceRight - sourceLeft;
        const sourceHeight = sourceBottom - sourceTop;
        const scale = Math.min(3, Math.max(1, 3200 / sourceWidth));
        const canvas = document.createElement('canvas');
        canvas.width = Math.max(1, Math.round(sourceWidth * scale));
        canvas.height = Math.max(1, Math.round(sourceHeight * scale));

        const context = canvas.getContext('2d');
        if (!context) throw new Error('Could not prepare the document image for OCR.');

        context.imageSmoothingEnabled = true;
        context.imageSmoothingQuality = 'high';
        context.filter = 'grayscale(1) contrast(1.5)';
        context.drawImage(
            bitmap,
            sourceLeft,
            sourceTop,
            sourceWidth,
            sourceHeight,
            0,
            0,
            canvas.width,
            canvas.height
        );
        return canvas;
    } finally {
        bitmap.close();
    }
}

async function recognizeMrzDocument(blob, statusDiv, documentType, countryCode, viewfinderCrop) {
    const tesseract = await getTesseract();
    let progressLabel = 'Reading the MRZ';
    const worker = await tesseract.createWorker('eng', 1, {
        workerPath: '/vendor/tesseract/worker.min.js',
        corePath: '/vendor/tesseract-core',
        logger: ({ status, progress }) => {
            if (status === 'recognizing text' && typeof progress === 'number') {
                statusDiv.innerText = `${progressLabel}... ${Math.round(progress * 100)}%`;
            }
        },
    });
    let mrzCanvas = null;
    const errors = [];

    try {
        try {
            mrzCanvas = await createDocumentMrzCrop(blob, documentType, viewfinderCrop);
        } catch (error) {
            console.warn('Could not preprocess the document MRZ; checking the full photo instead.', error);
        }

        if (mrzCanvas) {
            await worker.setParameters({
                tessedit_char_whitelist: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<',
                tessedit_pageseg_mode: 6,
            });
            const mrzRecognition = await worker.recognize(mrzCanvas);
            appendMrzDebugOutput('Viewfinder MRZ crop', mrzRecognition.data.text);
            const result = parseMrzText(
                mrzRecognition.data.text,
                documentType,
                countryCode
            );
            mrzRecognition.data.text = '';
            if (result.ok) return result;
            errors.push(result.error);
        }

        progressLabel = 'Checking the full photo for MRZ lines';
        statusDiv.innerText = 'Checking the full photo for MRZ lines...';
        await worker.setParameters({
            tessedit_char_whitelist: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<',
            tessedit_pageseg_mode: 3,
        });
        const fullRecognition = await worker.recognize(blob);
        appendMrzDebugOutput('Full photo fallback', fullRecognition.data.text);
        const result = parseMrzText(
            fullRecognition.data.text,
            documentType,
            countryCode
        );
        fullRecognition.data.text = '';
        if (result.ok) return result;
        errors.push(result.error);

        for (const error of [
            'invalid-check-digit',
            'country-mismatch',
            'expired',
            'invalid-date',
            'invalid-document-type',
        ]) {
            if (errors.includes(error)) return { ok: false, error };
        }
        return { ok: false, error: 'mrz-not-found' };
    } finally {
        if (mrzCanvas) {
            mrzCanvas.width = 0;
            mrzCanvas.height = 0;
        }
        await worker.terminate();
    }
}

function getMrzFailureMessage(error, documentType) {
    if (error === 'country-mismatch') return 'The MRZ issuing country does not match the selected country.';
    if (error === 'invalid-document-number') return 'The MRZ document number could not be verified. Retake the photo with the full MRZ in focus.';
    if (error === 'invalid-check-digit') return 'The MRZ check digits could not be verified. Retake the photo or use another document.';
    if (error === 'expired') return 'This document appears to be expired. Use a valid, unexpired document.';
    if (error === 'invalid-date') return 'The dates in the MRZ could not be verified. Retake the photo.';
    if (error === 'invalid-document-type') return 'The MRZ does not match the selected document type. Check the selection and retake the photo.';
    if (error === 'invalid-selection') return 'Select the document type and issuing country before continuing.';
    const framing = documentType === 'id-card' ? 'all three MRZ lines on the back of the card' : 'both MRZ lines';
    return `Could not read ${framing}. Retake the photo with every line sharp and fully in frame.`;
}

async function runBlindPassVerification() {
    const statusDiv = document.getElementById('status');
    const captureMessage = document.getElementById('captureMessage');
    const verifyBtn = document.getElementById('verifyBtn');
    const confirmButton = document.getElementById('confirmPasskeyBtn');
    pendingPhoneOutcome = null;
    confirmButton?.classList.add('hidden');
    verifyBtn?.classList.remove('hidden');
    captureMessage.classList.add('hidden');
    statusDiv.classList.remove('hidden');
    if (!isPhoneFlow && !isWalletScanMode) return;
    if (!capturedBlob) {
        statusDiv.innerText = 'Open the camera and take a photo before continuing.';
        return;
    }

    const documentType = document.getElementById('documentType').value;
    const countryCode = document.getElementById('documentCountry').value;
    if (!countryCode) {
        statusDiv.innerText = getMrzFailureMessage('invalid-selection', documentType);
        return;
    }

    verifyBtn.disabled = true;
    statusDiv.innerText = 'Preparing to verify the document MRZ...';

    try {
        const mrzResult = await recognizeMrzDocument(
            capturedBlob,
            statusDiv,
            documentType,
            countryCode,
            capturedViewfinderCrop
        );
        clearCapturedImage();

        if (!mrzResult.ok) {
            captureMessage.innerText = getMrzFailureMessage(mrzResult.error, documentType);
            captureMessage.classList.remove('hidden');
            statusDiv.classList.add('hidden');
            return;
        }

        const [year, month, day] = mrzResult.dateOfBirth.split('-').map(Number);
        const dobDate = new Date(year, month - 1, day);
        const today = new Date();
        let age = today.getFullYear() - dobDate.getFullYear();
        const m = today.getMonth() - dobDate.getMonth();
        if (m < 0 || (m === 0 && today.getDate() < dobDate.getDate())) {
            age--;
        }

        const isOver18 = age >= 18;
        pendingPhoneOutcome = {
            verified: true,
            documentType,
            issuingCountry: countryCode,
            isAdult: isOver18,
            expiresAt: mrzResult.expirationDate,
        };
        verifyBtn.classList.add('hidden');
        if (isWalletScanMode) {
            statusDiv.innerText = 'Saving your non-PII age-verification badge...';
            await saveWalletBadge(pendingPhoneOutcome);
            pendingPhoneOutcome = null;
            document.getElementById('phoneCard')?.classList.add('hidden');
            document.body.classList.remove('phone-flow');
            isWalletScanMode = false;
            await loadAccountDashboard();
            return;
        }
        if (confirmButton) {
            confirmButton.innerText = 'Complete verification';
            confirmButton.classList.remove('hidden');
        }
        statusDiv.innerText = 'ID checks passed. Continue to complete verification with your passkey.';
    } catch (error) {
        console.error('Verification error:', error);
        const message = error instanceof Error ? error.message : 'Unexpected processing error.';
        statusDiv.innerText = `Verification failed: ${message}`;
    } finally {
        clearCapturedImage();
        verifyBtn.disabled = false;
    }
}

window.addEventListener('DOMContentLoaded', () => {
    getPasskeyBrowser().catch((error) => {
        console.error('Could not preload the passkey library:', error);
    });
    populateDocumentCountries();
    initializeMrzDebugPanel();
    document.getElementById('documentType')?.addEventListener('change', updateDocumentFraming);
    updateDocumentFraming();

    const openCamBtn = document.getElementById('openCamBtn');
    const closeCamBtn = document.getElementById('closeCamBtn');
    const snapPhotoBtn = document.getElementById('snapPhotoBtn');
    const verifyBtn = document.getElementById('verifyBtn');
    const confirmPasskeyBtn = document.getElementById('confirmPasskeyBtn');
    const clearDebugBtn = document.getElementById('clearMrzDebugBtn');
    const cancelVerificationBtn = document.getElementById('cancelVerificationBtn');
    const passkeyLoginBtn = document.getElementById('passkeyLoginBtn');
    const profileAvatarBtn = document.getElementById('profileAvatarBtn');
    const profileScanBtn = document.getElementById('profileScanBtn');
    const profilePasskeyBtn = document.getElementById('profilePasskeyBtn');
    const profileSignOutBtn = document.getElementById('profileSignOutBtn');
    const walletVerifyBtn = document.getElementById('walletVerifyBtn');
    const walletScanPhoneBtn = document.getElementById('walletScanPhoneBtn');
    const walletCancelBtn = document.getElementById('walletCancelBtn');
    const passkeyModalSaveBtn = document.getElementById('passkeyModalSaveBtn');
    const passkeyModalCloseBtn = document.getElementById('passkeyModalCloseBtn');
    const passkeyModalNotNowBtn = document.getElementById('passkeyModalNotNowBtn');
    const desktopReturnBtn = document.getElementById('desktopReturnBtn');

    if (openCamBtn) openCamBtn.addEventListener('click', openIdCamera);
    if (closeCamBtn) closeCamBtn.addEventListener('click', closeIdCamera);
    if (snapPhotoBtn) snapPhotoBtn.addEventListener('click', captureIdPhoto);
    if (verifyBtn) verifyBtn.addEventListener('click', runBlindPassVerification);
    if (confirmPasskeyBtn) confirmPasskeyBtn.addEventListener('click', confirmPhonePasskey);
    if (passkeyLoginBtn) passkeyLoginBtn.addEventListener('click', signInWithPasskey);
    if (profileAvatarBtn) {
        profileAvatarBtn.addEventListener('click', () => showProfilePopover());
    }
    if (profileScanBtn) profileScanBtn.addEventListener('click', startWalletScan);
    if (profilePasskeyBtn) {
        profilePasskeyBtn.addEventListener('click', () => saveProfilePasskey(profilePasskeyBtn));
    }
    if (profileSignOutBtn) profileSignOutBtn.addEventListener('click', signOut);
    if (walletVerifyBtn) walletVerifyBtn.addEventListener('click', verifyWalletFromRequest);
    if (walletScanPhoneBtn) {
        walletScanPhoneBtn.addEventListener('click', showPhoneQrForSession);
    }
    if (walletCancelBtn) {
        walletCancelBtn.addEventListener('click', () => cancelDesktopVerification(walletCancelBtn));
    }
    if (passkeyModalSaveBtn) {
        passkeyModalSaveBtn.addEventListener('click', () => saveProfilePasskey(passkeyModalSaveBtn));
    }
    if (passkeyModalCloseBtn) {
        passkeyModalCloseBtn.addEventListener('click', () => closePasskeyModal(true));
    }
    if (passkeyModalNotNowBtn) {
        passkeyModalNotNowBtn.addEventListener('click', () => closePasskeyModal(true));
    }
    if (desktopReturnBtn) {
        desktopReturnBtn.addEventListener('click', (event) => {
            if (desktopReturnBtn.dataset.returnUrl) return;
            event.preventDefault();
            window.history.back();
        });
    }
    document.addEventListener('click', (event) => {
        if (!(event.target instanceof Element) || !event.target.closest('#profileMenu')) {
            showProfilePopover(false);
        }
    });
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            showProfilePopover(false);
            closePasskeyModal(true);
        }
    });
    if (clearDebugBtn) clearDebugBtn.addEventListener('click', clearMrzDebugOutput);
    if (cancelVerificationBtn) {
        cancelVerificationBtn.addEventListener('click', cancelDesktopVerification);
    }

    initBlindPassSession();
});

window.addEventListener('pagehide', () => {
    desktopPollingStopped = true;
    phonePollingStopped = true;
    if (desktopPollTimeout) window.clearTimeout(desktopPollTimeout);
    if (phonePollTimeout) window.clearTimeout(phonePollTimeout);
    clearCapturedImage();
});