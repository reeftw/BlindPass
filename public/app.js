// Initialize Supabase
const SUPABASE_URL = 'https://cersffyrlkbcodpaavwc.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_0-oBEj92saQbsDb-kauZrg_y4DTTXKa';
const supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

const params = new URLSearchParams(window.location.search);
const sessionId = params.get('session');

let capturedBlob = null;
let cameraStream = null;
let verifierReturnUrl = '/verifier.html';
let verifierName = 'Verifier';

async function initBlindPassSession() {
    const sessionBanner = document.getElementById('sessionBanner');
    const loginCard = document.getElementById('loginCard');
    const verifyCard = document.getElementById('verifyCard');
    const loggedInUser = document.getElementById('loggedInUser');
    const googleLink = document.getElementById('googleLoginLink');
    const msLink = document.getElementById('msLoginLink');

    if (!sessionId) {
        if (sessionBanner) {
            sessionBanner.innerText = 'No session ID found. Open /verifier.html to start.';
        }
        return;
    }

    if (googleLink) googleLink.href = `/auth/google?session=${encodeURIComponent(sessionId)}`;
    if (msLink) msLink.href = `/auth/microsoft?session=${encodeURIComponent(sessionId)}`;

    try {
        const res = await fetch(`/api/session/${encodeURIComponent(sessionId)}`);
        if (!res.ok) {
            if (sessionBanner) sessionBanner.innerText = 'Session not found. Start from the verifier page.';
            return;
        }
        const session = await res.json();
        verifierReturnUrl = session.returnTo || '/verifier.html';
        verifierName = session.verifier || 'Verifier';

        if (sessionBanner) {
            sessionBanner.innerText = `Requested by: ${verifierName}`;
        }

        if (session.loggedIn) {
            if (loginCard) loginCard.classList.add('hidden');
            if (verifyCard) verifyCard.classList.remove('hidden');
            if (loggedInUser) {
                loggedInUser.innerText = `Signed in via ${session.provider.toUpperCase()} (${session.email})`;
            }
        }
    } catch (err) {
        console.error('Session load error:', err);
    }
}

async function openIdCamera() {
    const video = document.getElementById('cameraVideo');
    const snapBtn = document.getElementById('snapPhotoBtn');
    const statusDiv = document.getElementById('status');

    try {
        cameraStream = await navigator.mediaDevices.getUserMedia({
            video: { facingMode: 'environment' },
        });
        video.srcObject = cameraStream;
        video.classList.remove('hidden');
        snapBtn.classList.remove('hidden');
        statusDiv.innerText = 'Status: Camera opened. Click Photo to capture ID.';
    } catch (err) {
        statusDiv.innerText = `Status: Camera unavailable (${err.message}). Select an image file instead.`;
    }
}

function captureIdPhoto() {
    const video = document.getElementById('cameraVideo');
    const canvas = document.getElementById('photoCanvas');
    const preview = document.getElementById('photoPreview');
    const snapBtn = document.getElementById('snapPhotoBtn');
    const statusDiv = document.getElementById('status');

    if (!video || !video.videoWidth) return;

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0);

    canvas.toBlob((blob) => {
        if (!blob) return;
        capturedBlob = blob;
        preview.src = URL.createObjectURL(blob);
        preview.classList.remove('hidden');
        statusDiv.innerText = 'Status: Photo captured. Click Verify ID to run OCR.';
    }, 'image/jpeg', 0.92);

    if (cameraStream) {
        cameraStream.getTracks().forEach((track) => track.stop());
        cameraStream = null;
    }
    video.classList.add('hidden');
    snapBtn.classList.add('hidden');
}

function extractNameFromText(text) {
    const lines = text.split('\n').map((l) => l.trim()).filter(Boolean);

    for (const line of lines) {
        const compact = line.replace(/\s+/g, '');
        const mrzMatch = compact.match(/^[A-Z0-9<]{2}[A-Z<]{3}([A-Z]+)<<([A-Z<]+)/);
        if (mrzMatch) {
            const surname = mrzMatch[1].replace(/<+/g, ' ').trim();
            const given = mrzMatch[2].replace(/<+/g, ' ').trim();
            const full = `${given} ${surname}`.trim();
            if (full.length >= 2) return full;
        }
    }

    return 'Not detected';
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
    const fileInput = document.getElementById('idFile');
    const statusDiv = document.getElementById('status');
    const resultCard = document.getElementById('resultCard');
    const outName = document.getElementById('outName');
    const outDob = document.getElementById('outDob');
    const outOver18 = document.getElementById('outOver18');
    const backBtn = document.getElementById('backToVerifierBtn');

    const hasFile = fileInput && fileInput.files && fileInput.files.length > 0;
    if (!hasFile && !capturedBlob) {
        alert('Please open the camera and click a photo, or select a synthetic ID image first.');
        return;
    }

    let imageSource = hasFile ? fileInput.files[0] : capturedBlob;
    statusDiv.innerText = 'Status: Initializing local OCR (Tesseract.js)...';

    try {
        // 1. Run Tesseract.js locally in browser memory (RAM)
        let { data: { text } } = await Tesseract.recognize(
            imageSource,
            'eng',
            { logger: (m) => console.log(m) }
        );

        statusDiv.innerText = 'Status: Parsing Name and Date of Birth locally...';

        // 2. Extract Name and Date of Birth
        const detectedName = extractNameFromText(text);
        const dobString = extractDobFromText(text);

        if (!dobString) {
            statusDiv.innerText = 'Status Error: Could not detect a valid Date of Birth. Try another image.';
            text = null;
            imageSource = null;
            return;
        }

        statusDiv.innerText = 'Status: DOB Found! Evaluating zero-knowledge condition...';

        // 3. Zero-Knowledge Age Logic: Calculate if user is >= 18
        const dobDate = new Date(dobString);
        const today = new Date();
        let age = today.getFullYear() - dobDate.getFullYear();
        const m = today.getMonth() - dobDate.getMonth();
        if (m < 0 || (m === 0 && today.getDate() < dobDate.getDate())) {
            age--;
        }

        const isOver18 = age >= 18;

        // Display Name, DOB, and 18+ status in the UI
        if (outName) outName.innerText = detectedName;
        if (outDob) outDob.innerText = dobString;
        if (outOver18) outOver18.innerText = isOver18 ? 'Yes (18+)' : 'No (Under 18)';
        if (resultCard) resultCard.classList.remove('hidden');

        if (backBtn) {
            const target = new URL(verifierReturnUrl, window.location.origin);
            target.searchParams.set('verified', '1');
            target.searchParams.set('is_over_18', String(isOver18));
            backBtn.href = target.toString();
            backBtn.innerText = `Back to ${verifierName}`;
        }

        // 4. MEMORY PURGE: Explicitly clear heavy variables to protect user RAM
        text = null;
        imageSource = null;
        capturedBlob = null;
        console.log('Memory Purged: Raw image buffers and OCR text dropped.');

        statusDiv.innerText = `Status: Age Verified! Is over 18: ${isOver18}. Saving boolean token...`;

        // 5. Send ONLY the boolean verification token to Supabase
        await saveTokenToSupabase(isOver18);
    } catch (error) {
        console.error('Verification error:', error);
        statusDiv.innerText = 'Status Error: Processing failed.';
    }
}

async function saveTokenToSupabase(isOver18) {
    const statusDiv = document.getElementById('status');

    const { data, error } = await supabaseClient
        .from('verifications')
        .insert([
            { is_over_18: isOver18 }
        ]);

    if (error) {
        statusDiv.innerText = `Status Error saving to database: ${error.message}`;
    } else {
        statusDiv.innerText = 'Success! Zero-knowledge boolean token securely stored in Supabase. (PII Stored: None)';
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