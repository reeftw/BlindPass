const SUPABASE_URL = 'https://cersffyrlkbcodpaavwc.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_0-oBEj92saQbsDb-kauZrg_y4DTTXKa';
const scriptLoads = new Map();
let supabaseClient = null;

const params = new URLSearchParams(window.location.search);
const sessionId = params.get('session');
const isPhoneFlow = params.get('mode') === 'phone';

let capturedBlob = null;
let cameraStream = null;
let verifierName = 'Verifier';
let desktopPollTimeout = null;
let desktopPollingStopped = false;
let verificationRedirectStarted = false;

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
            reject(new Error(`Could not load a required verification library (${new URL(src).hostname}).`));
        }, { once: true });
    });

    scriptLoads.set(src, loadPromise);
    document.head.appendChild(script);
    return loadPromise;
}

async function getTesseract() {
    await loadExternalScript(
        'https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js',
        () => Boolean(window.Tesseract)
    );
    if (!window.Tesseract) throw new Error('The local OCR library did not initialize.');
    return window.Tesseract;
}

async function getSupabaseClient() {
    if (supabaseClient) return supabaseClient;
    await loadExternalScript(
        'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2',
        () => Boolean(window.supabase?.createClient)
    );
    if (!window.supabase?.createClient) throw new Error('The database client did not initialize.');
    supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
    return supabaseClient;
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
    const qrImage = document.getElementById('phoneQrCode');
    const desktopStatus = document.getElementById('desktopStatus');
    const phoneControls = document.getElementById('phoneControls');
    const phoneDone = document.getElementById('phoneDone');

    if (isPhoneFlow) {
        document.body.classList.add('phone-flow');
        loginCard?.classList.add('hidden');
        verifyCard?.classList.add('hidden');
        phoneCard?.classList.remove('hidden');
    }

    if (!sessionId) {
        const message = 'This phone link is incomplete. Return to the requesting site and scan its QR code again.';
        if (isPhoneFlow && phoneStatus) phoneStatus.innerText = message;
        else if (sessionBanner) sessionBanner.innerText = 'No session ID found. Open /verifier.html to start.';
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
        const session = await res.json();
        verifierName = session.verifier || 'Verifier';

        if (isPhoneFlow) {
            if (!session.loggedIn) {
                if (phoneStatus) phoneStatus.innerText = 'Return to your computer, sign in, then scan the new QR code.';
                return;
            }
            if (phoneAccount) {
                phoneAccount.innerText = `Signed in via ${session.provider.toUpperCase()} (${session.email})`;
            }
            if (session.verified) {
                phoneControls?.classList.add('hidden');
                phoneDone?.classList.remove('hidden');
                if (phoneStatus) phoneStatus.innerText = 'This verification is already complete.';
                return;
            }
            if (session.appOrigin !== window.location.origin || !session.phoneReady) {
                if (phoneStatus) {
                    phoneStatus.innerText = 'Open this link from the configured HTTPS site to use the phone camera.';
                }
                return;
            }
            phoneControls?.classList.remove('hidden');
            if (phoneStatus) phoneStatus.innerText = 'Your ID image stays on this phone. Open the camera when you are ready.';
            return;
        }

        if (sessionBanner) {
            sessionBanner.innerText = `Requested by: ${verifierName}`;
        }

        if (session.loggedIn) {
            loginCard?.classList.add('hidden');
            verifyCard?.classList.remove('hidden');
            if (loggedInUser) {
                loggedInUser.innerText = `Signed in via ${session.provider.toUpperCase()} (${session.email})`;
            }

            if (session.verified) {
                redirectDesktopToRequester(session);
                return;
            }
            if (!session.phoneReady) {
                showQrUnavailable('Phone verification requires HTTPS. Configure APP_ORIGIN with your HTTPS site URL before using the QR flow.');
                return;
            }
            if (session.appOrigin !== window.location.origin) {
                showQrUnavailable(`Open this page at ${session.appOrigin} to create a phone link for this session.`);
                return;
            }

            if (qrImage) {
                qrImage.src = `/api/session/${encodeURIComponent(sessionId)}/qr`;
            }
            if (desktopStatus) desktopStatus.innerText = 'Scan this code with your phone camera to continue.';
            startDesktopPolling();
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
    if (qrUnavailable) {
        qrUnavailable.innerText = message;
        qrUnavailable.classList.remove('hidden');
    }
}

function redirectDesktopToRequester(session) {
    if (verificationRedirectStarted) return;
    verificationRedirectStarted = true;
    const target = new URL(session.returnTo || '/verifier.html', session.appOrigin || window.location.origin);
    target.searchParams.set('verified', '1');
    target.searchParams.set('is_over_18', String(session.isOver18));

    const desktopStatus = document.getElementById('desktopStatus');
    if (desktopStatus) desktopStatus.innerText = `Verification complete. Returning to ${verifierName}...`;
    window.setTimeout(() => window.location.assign(target.toString()), 1200);
}

function startDesktopPolling() {
    desktopPollingStopped = false;
    pollDesktopVerification();
}

async function pollDesktopVerification() {
    if (desktopPollingStopped || verificationRedirectStarted) return;

    try {
        const res = await fetch(`/api/session/${encodeURIComponent(sessionId)}`, { cache: 'no-store' });
        if (res.status === 404) {
            const desktopStatus = document.getElementById('desktopStatus');
            if (desktopStatus) desktopStatus.innerText = 'This verification session has expired. Start again from the requesting site.';
            desktopPollingStopped = true;
            return;
        }
        if (!res.ok) {
            throw new Error(`Session status request failed (${res.status})`);
        }

        const session = await res.json();
        if (session.verified) {
            redirectDesktopToRequester(session);
            return;
        }
    } catch (err) {
        console.error('Verification status check failed:', err);
        const desktopStatus = document.getElementById('desktopStatus');
        if (desktopStatus) desktopStatus.innerText = 'Connection interrupted. Checking again...';
    } finally {
        if (!desktopPollingStopped && !verificationRedirectStarted) {
            desktopPollTimeout = window.setTimeout(pollDesktopVerification, 2000);
        }
    }
}

async function openIdCamera() {
    const video = document.getElementById('cameraVideo');
    const snapBtn = document.getElementById('snapPhotoBtn');
    const statusDiv = document.getElementById('status');

    try {
        if (!navigator.mediaDevices?.getUserMedia) {
            throw new Error('Camera access requires HTTPS on your phone');
        }
        cameraStream = await navigator.mediaDevices.getUserMedia({
            video: { facingMode: 'environment' },
        });
        video.srcObject = cameraStream;
        video.classList.remove('hidden');
        snapBtn.classList.remove('hidden');
        statusDiv.innerText = 'Camera ready. Center your ID and take a photo.';
    } catch (err) {
        statusDiv.innerText = `Camera unavailable: ${err.message}. Open this link on your phone over HTTPS.`;
    }
}

function captureIdPhoto() {
    const video = document.getElementById('cameraVideo');
    const canvas = document.getElementById('photoCanvas');
    const preview = document.getElementById('photoPreview');
    const snapBtn = document.getElementById('snapPhotoBtn');
    const statusDiv = document.getElementById('status');

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
        statusDiv.innerText = 'Photo captured on this phone. Select Verify ID to continue.';
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
    document.getElementById('snapPhotoBtn')?.classList.add('hidden');
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
    capturedBlob = null;
}

function extractDobFromText(text) {
    const lines = text.split('\n').map((l) => l.replace(/\s+/g, ''));

    for (const line of lines) {
        const mrzMatch = line.match(/(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d[MFX]/);
        if (mrzMatch) {
            const yy = mrzMatch[1];
            const mm = mrzMatch[2];
            const dd = mrzMatch[3];
            const fullYear = parseInt(yy, 10) > 50 ? `19${yy}` : `20${yy}`;
            return `${fullYear}-${mm}-${dd}`;
        }
    }

    const visualMatch = text.match(
        /\b(0[1-9]|[12]\d|3[01])\s+(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)\s+(\d{2}|\d{4})\b/i
    );
    if (visualMatch) {
        const day = visualMatch[1];
        const months = {
            JAN: '01', FEB: '02', MAR: '03', APR: '04', MAY: '05', JUN: '06',
            JUL: '07', AUG: '08', SEP: '09', OCT: '10', NOV: '11', DEC: '12',
        };
        const mm = months[visualMatch[2].toUpperCase()];
        let year = visualMatch[3];
        if (year.length === 2) {
            year = parseInt(year, 10) > 50 ? `19${year}` : `20${year}`;
        }
        return `${year}-${mm}-${day}`;
    }

    const numericMatch =
        text.match(/\b(19|20)\d{2}[-/.](0[1-9]|1[0-2])[-/.](0[1-9]|[12]\d|3[01])\b/) ||
        text.match(/\b(0[1-9]|[12]\d|3[01])[-/.](0[1-9]|1[0-2])[-/.](19|20)\d{2}\b/);

    return numericMatch ? numericMatch[0] : null;
}

async function runBlindPassVerification() {
    const statusDiv = document.getElementById('status');
    const verifyBtn = document.getElementById('verifyBtn');
    if (!isPhoneFlow) return;
    if (!capturedBlob) {
        statusDiv.innerText = 'Open the camera and take a photo before continuing.';
        return;
    }

    verifyBtn.disabled = true;
    statusDiv.innerText = 'Reading the ID locally on this phone...';
    let tokenSaved = false;

    try {
        const tesseract = await getTesseract();
        const recognition = await tesseract.recognize(
            capturedBlob,
            'eng',
            { logger: (m) => console.log(m) }
        );
        const dobString = extractDobFromText(recognition.data.text);
        recognition.data.text = '';
        clearCapturedImage();

        if (!dobString) {
            statusDiv.innerText = 'Could not detect a valid date of birth. Open the camera and try another photo.';
            return;
        }

        const dobDate = new Date(dobString);
        const today = new Date();
        let age = today.getFullYear() - dobDate.getFullYear();
        const m = today.getMonth() - dobDate.getMonth();
        if (m < 0 || (m === 0 && today.getDate() < dobDate.getDate())) {
            age--;
        }

        const isOver18 = age >= 18;

        statusDiv.innerText = 'Saving the age-verification result...';
        await saveTokenToSupabase(isOver18);
        tokenSaved = true;

        const response = await fetch(`/api/session/${encodeURIComponent(sessionId)}/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ isOver18 }),
        });
        if (!response.ok) {
            let errorMessage = `Could not notify the requesting website (${response.status}).`;
            try {
                const result = await response.json();
                if (result.error) errorMessage = result.error;
            } catch {
                // Keep the explicit status-based message if the response isn't JSON.
            }
            throw new Error(errorMessage);
        }

        document.getElementById('phoneControls')?.classList.add('hidden');
        const phoneDone = document.getElementById('phoneDone');
        if (phoneDone) {
            phoneDone.innerText = isOver18
                ? 'Verification is complete. Return to your computer; the requesting website will update automatically.'
                : 'Verification is complete. Return to your computer; the requesting website will show the result.';
            phoneDone.classList.remove('hidden');
        }
        statusDiv.innerText = 'Verification complete.';
    } catch (error) {
        console.error('Verification error:', error);
        const message = error instanceof Error ? error.message : 'Unexpected processing error.';
        statusDiv.innerText = tokenSaved
            ? `The result was saved, but this session could not be completed. ${message} Return to your computer and restart verification.`
            : `Verification failed: ${message}`;
    } finally {
        clearCapturedImage();
        verifyBtn.disabled = false;
    }
}

async function saveTokenToSupabase(isOver18) {
    const client = await getSupabaseClient();
    const { error } = await client
        .from('verifications')
        .insert([
            { is_over_18: isOver18 }
        ]);

    if (error) {
        throw new Error(`Could not save the verification result: ${error.message}`);
    }
}

window.addEventListener('DOMContentLoaded', () => {
    const openCamBtn = document.getElementById('openCamBtn');
    const snapPhotoBtn = document.getElementById('snapPhotoBtn');
    const verifyBtn = document.getElementById('verifyBtn');

    if (openCamBtn) openCamBtn.addEventListener('click', openIdCamera);
    if (snapPhotoBtn) snapPhotoBtn.addEventListener('click', captureIdPhoto);
    if (verifyBtn) verifyBtn.addEventListener('click', runBlindPassVerification);

    initBlindPassSession();
});

window.addEventListener('pagehide', () => {
    desktopPollingStopped = true;
    if (desktopPollTimeout) window.clearTimeout(desktopPollTimeout);
    clearCapturedImage();
});