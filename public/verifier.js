const STATE_KEY = 'blindpass.verifier-state';
const params = new URLSearchParams(window.location.search);
const verifierToken = params.get('verifier_token');
const returnedState = params.get('state');
const wasCancelled = params.get('cancelled') === 'true';
const statusEl = document.getElementById('status');
const startUrl = new URL('/start', window.location.origin);

function createState() {
    return window.crypto.randomUUID().replace(/-/g, '_');
}

function setResult(isAdult) {
    statusEl.textContent = '';
    const message = document.createElement('span');
    message.className = isAdult ? 'ok' : 'no';
    message.textContent = isAdult
        ? 'Verified (18+: true)'
        : 'Not 18+ (18+: false)';
    statusEl.append('Status: ', message);
}

startUrl.searchParams.set('verifier', 'Discord');
startUrl.searchParams.set(
    'return_url',
    `${window.location.origin}${window.location.pathname}`
);
document.getElementById('blindPassLink').href = startUrl.toString();

if (window.location.search) {
    window.history.replaceState(null, '', window.location.pathname);
}

if (wasCancelled) {
    statusEl.textContent = 'Status: Verification cancelled.';
} else if (verifierToken) {
    const expectedState = window.sessionStorage.getItem(STATE_KEY);
    if (!expectedState || returnedState !== expectedState) {
        statusEl.textContent = 'Status: Verification could not be confirmed.';
    } else {
        window.sessionStorage.removeItem(STATE_KEY);
        fetch('/api/verifier/verify-token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            cache: 'no-store',
            body: JSON.stringify({ token: verifierToken, state: returnedState }),
        })
            .then(async (response) => {
                const result = await response.json();
                if (!response.ok) throw new Error(result.error || 'Invalid result');
                setResult(result.isAdult === true);
            })
            .catch((error) => {
                console.error('Could not confirm verifier result:', error);
                statusEl.textContent = 'Status: Verification could not be confirmed.';
            });
    }
}

if (!verifierToken && !wasCancelled) {
    const state = createState();
    window.sessionStorage.setItem(STATE_KEY, state);
    startUrl.searchParams.set('state', state);
    document.getElementById('blindPassLink').href = startUrl.toString();
}
