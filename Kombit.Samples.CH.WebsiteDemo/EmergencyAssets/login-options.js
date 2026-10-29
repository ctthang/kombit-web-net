(function () {
    'use strict';
    // "Other login options" on login.ashx. The card is revealed only when this browser holds an
    // emergency credential that the server still accepts, and its button runs the emergency key
    // check in place: one WebAuthn prompt, then the emergency home page. Discovery is read-only:
    // it never creates browser storage, never contacts Identify, and never prompts for a key.
    const card = document.getElementById('emergency-login-option');
    if (!card) return;
    // With a single (or default) IdP the page is shown only to offer emergency login. When this
    // browser has no active key, continue to that IdP as if the page had never been shown.
    const proceed = () => {
        if (card.dataset.continue) location.replace(card.dataset.continue);
    };
    if (!window.indexedDB || !window.PublicKeyCredential || !window.fetch) {
        proceed();
        return;
    }
    const actions = document.getElementById('emergency-login-actions');
    const status = document.getElementById('emergency-login-status');

    const messages = {
        credential_unavailable: 'This emergency key is no longer active. Prepare it again after a normal login.',
        csrf_or_origin_rejected: 'The request was rejected. Reload the page and try again.',
        key_proof_rejected: 'The key check was rejected.',
        proof_expired: 'The key check took too long. Try again.',
        state_changed_retry: 'The key state changed. Try again.',
    };

    function show(text, tone) {
        status.textContent = text || '';
        status.dataset.tone = tone || 'info';
        status.hidden = !text;
    }

    function bytes(value) {
        const base64 =
            value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4);
        return Uint8Array.from(atob(base64), character => character.charCodeAt(0));
    }

    function text(value) {
        return btoa(String.fromCharCode(...new Uint8Array(value)))
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');
    }

    // Steer the browser to the configured authenticator so it can skip its chooser.
    // EmergencyCredential.Authenticator: security-key | platform | any (no change).
    // Registration also pins the attachment. Login only adds a hint: transports are a hard
    // filter, so login uses the transports the key itself reported at registration instead.
    function applyAuthenticator(options, ceremony) {
        const kind = card.dataset.authenticator;
        if (kind !== 'security-key' && kind !== 'platform') return options;
        const roaming = kind === 'security-key';
        options.hints = [roaming ? 'security-key' : 'client-device'];
        if (ceremony === 'create') {
            options.authenticatorSelection = Object.assign({}, options.authenticatorSelection, {
                authenticatorAttachment: roaming ? 'cross-platform' : 'platform',
            });
        }
        return options;
    }

    async function send(operation, values) {
        const response = await fetch(card.dataset.api + '?op=' + encodeURIComponent(operation), {
            method: 'POST',
            credentials: 'same-origin',
            redirect: 'error',
            headers: { 'Content-Type': 'application/json', 'X-Emergency-CSRF': card.dataset.csrf },
            body: JSON.stringify(values || {}),
        });
        let value = {};
        try {
            value = await response.json();
        } catch (_) {}
        if (!response.ok) {
            const code = value.error || 'request_failed';
            const reference =
                typeof value.reference_id === 'string'
                    ? value.reference_id
                    : response.headers.get('X-Emergency-Reference');
            const error = new Error(
                (messages[code] || 'Emergency login failed.') +
                    ' (Error: ' + code + '; HTTP ' + response.status +
                    (reference ? '; Reference: ' + reference : '') + ')',
            );
            error.code = code;
            throw error;
        }
        return value;
    }

    function storedEntries() {
        return new Promise(resolve => {
            let request;
            try {
                request = indexedDB.open('saml-emergency-credentials-v1', 1);
            } catch (_) {
                resolve([]);
                return;
            }
            request.onupgradeneeded = event => {
                // No database yet means no prepared key; do not create an empty one.
                if (event.oldVersion === 0) request.transaction.abort();
            };
            request.onerror = request.onblocked = () => resolve([]);
            request.onsuccess = () => {
                const database = request.result;
                if (!database.objectStoreNames.contains('entries')) {
                    database.close();
                    resolve([]);
                    return;
                }
                const transaction = database.transaction('entries', 'readonly');
                const all = transaction.objectStore('entries').getAll();
                transaction.oncomplete = () => {
                    database.close();
                    resolve(all.result || []);
                };
                transaction.onerror = transaction.onabort = () => {
                    database.close();
                    resolve([]);
                };
            };
        });
    }

    async function isActive(entry) {
        try {
            const value = await send('login-status', { emergency_credential: entry.emergency_credential });
            return value.active === true;
        } catch (_) {
            return false;
        }
    }

    async function activeKeys() {
        const now = Date.now();
        // Newest stored credential per key; renewals leave older copies behind in the browser.
        const newest = new Map();
        for (const entry of await storedEntries()) {
            if (
                !entry ||
                typeof entry.emergency_credential !== 'string' ||
                typeof entry.binding_id !== 'string' ||
                typeof entry.expires_at !== 'number' ||
                entry.expires_at * 1000 <= now
            )
                continue;
            const current = newest.get(entry.binding_id);
            if (!current || entry.expires_at > current.expires_at) newest.set(entry.binding_id, entry);
        }
        const active = [];
        for (const entry of newest.values()) if (await isActive(entry)) active.push(entry);
        return active;
    }

    async function login(entry) {
        const pending = await send('login-options', { emergency_credential: entry.emergency_credential });
        const options = pending.publicKey;
        options.challenge = bytes(options.challenge);
        options.allowCredentials.forEach(key => (key.id = bytes(key.id)));
        // Transports the key reported at registration (newer setups store them).
        if (Array.isArray(entry.transports) && entry.transports.length)
            options.allowCredentials.forEach(key => (key.transports = entry.transports.slice()));
        applyAuthenticator(options, 'get');
        const started = Date.now();
        let key;
        try {
            key = await navigator.credentials.get({ publicKey: options });
        } catch (error) {
            // Keep what the browser was asked for, so an instant refusal can be explained.
            error.webauthnMs = Date.now() - started;
            console.warn('Emergency login: the browser rejected the key check.', {
                name: error.name,
                message: error.message,
                afterMs: error.webauthnMs,
                hints: options.hints || null,
                transports: options.allowCredentials.map(item => item.transports || null),
            });
            throw error;
        }
        const response = key.response;
        const result = await send('login-complete', {
            transaction_id: pending.transaction_id,
            credential: {
                id: key.id,
                rawId: text(key.rawId),
                type: key.type,
                clientExtensionResults: key.getClientExtensionResults(),
                response: {
                    clientDataJSON: text(response.clientDataJSON),
                    authenticatorData: text(response.authenticatorData),
                    signature: text(response.signature),
                    userHandle: response.userHandle ? text(response.userHandle) : null,
                },
            },
        });
        location.assign(result.redirect);
    }

    function button(label, entry) {
        const element = document.createElement('button');
        element.type = 'button';
        element.className = 'btn btn-default login-alt-button';
        element.textContent = label;
        element.addEventListener('click', async () => {
            const buttons = actions.querySelectorAll('button');
            buttons.forEach(item => (item.disabled = true));
            show('Confirm with your security key or passkey...', 'busy');
            try {
                await login(entry);
            } catch (error) {
                show(
                    error.name === 'NotAllowedError' && error.webauthnMs < 1500
                        ? 'The browser refused the key check without showing a prompt (' +
                          error.name + ': ' + error.message + '). Use the browser where this ' +
                          'key was set up, or check that it can use your passkey or security key.'
                        : error.name === 'NotAllowedError'
                        ? 'Key check cancelled or timed out. Try again when your key is ready.'
                        : error.message || 'Emergency login failed.',
                    'error',
                );
                buttons.forEach(item => (item.disabled = false));
            }
        });
        return element;
    }

    (async function () {
        try {
            const keys = await activeKeys();
            if (!keys.length) {
                proceed();
                return;
            }
            keys.sort((a, b) => b.expires_at - a.expires_at);
            actions.replaceChildren(
                ...keys.map(entry =>
                    button(
                        keys.length === 1
                            ? 'Emergency login'
                            : 'Emergency login with key ...' + entry.binding_id.slice(-6),
                        entry,
                    ),
                ),
            );
            card.hidden = false;
        } catch (_) {
            // Any failure keeps the card hidden; normal login is unaffected.
            proceed();
        }
    })();
})();
