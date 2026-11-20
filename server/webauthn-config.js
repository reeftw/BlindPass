import { isIP } from 'node:net';

function isLocalHttpOrigin(origin) {
    return origin.protocol === 'http:' &&
        ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname);
}

export function resolveWebAuthnConfig({
    port = 3000,
    appOrigin,
    renderExternalUrl,
    rpID,
    nodeEnv,
} = {}) {
    if (!appOrigin && !renderExternalUrl && nodeEnv === 'production') {
        throw new Error('APP_ORIGIN or RENDER_EXTERNAL_URL must be configured in production');
    }
    const originUrl = new URL(
        appOrigin || renderExternalUrl || `http://localhost:${port}`
    );
    if (
        (originUrl.protocol !== 'https:' && !isLocalHttpOrigin(originUrl)) ||
        originUrl.pathname !== '/' ||
        originUrl.search ||
        originUrl.hash ||
        originUrl.username ||
        originUrl.password
    ) {
        throw new Error(
            'APP_ORIGIN must be an HTTPS origin (HTTP is allowed only for localhost development)'
        );
    }

    const resolvedRpID = (rpID || originUrl.hostname).toLowerCase();
    let rpUrl;
    try {
        rpUrl = new URL(`https://${resolvedRpID}`);
    } catch {
        throw new Error('RP_ID must be a hostname without a scheme, port, or path');
    }
    if (
        !resolvedRpID ||
        isIP(resolvedRpID) ||
        rpUrl.hostname !== resolvedRpID ||
        rpUrl.pathname !== '/' ||
        rpUrl.search ||
        rpUrl.hash
    ) {
        throw new Error('RP_ID must be a DNS hostname without a scheme, port, or path');
    }
    if (
        originUrl.hostname !== resolvedRpID &&
        !originUrl.hostname.endsWith(`.${resolvedRpID}`)
    ) {
        throw new Error('RP_ID must match APP_ORIGIN or be its parent domain');
    }

    return {
        configuredOrigin: originUrl,
        expectedOrigin: originUrl.origin,
        rpID: resolvedRpID,
    };
}
