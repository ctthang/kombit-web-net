(function () {
    'use strict';
    // "Other login options" on login.ashx. The card is revealed only when this browser has set
    // up an emergency key that the server still accepts, and its button runs the emergency key
    // check in place: one passkey prompt, then the emergency home page. The browser holds no
    // emergency credential; a non-secret marker (binding ID) says which keys it set up, and the
    // passkey identifies the key at login. Discovery never contacts Identify or prompts for a key.
    const card = document.getElementById('emergency-login-option');
    if (!card) return;
    // With a single (or default) IdP the page is shown only to offer emergency login. When this
    // browser has no active key, continue to that IdP as if the page had never been shown.
    const proceed = () => {
        if (card.dataset.continue) location.replace(card.dataset.continue);
    };
    if (!window.PublicKeyCredential || !window.fetch) {
        proceed();
        return;
    }
    const actions = document.getElementById('emergency-login-actions');
    const status = document.getElementById('emergency-login-status');

    const messages = {
        credential_unavailable: 'This passkey is not an active emergency key. Set up emergency access again after a normal login.',
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
    // Registration also pins the attachment. Login only adds a hint: it names no key, so there
    // are no transports to restrict.
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

    const markerKey = 'saml-emergency-login-v1';

    function readMarker() {
        try {
            const list = JSON.parse(localStorage.getItem(markerKey) || '[]');
            return Array.isArray(list) ? list.filter(item => item && typeof item.binding_id === 'string') : [];
        } catch (_) {
            return [];
        }
    }

    function forget(bindingIds) {
        try {
            const list = readMarker().filter(item => !bindingIds.includes(item.binding_id));
            if (list.length) localStorage.setItem(markerKey, JSON.stringify(list));
            else localStorage.removeItem(markerKey);
        } catch (_) {}
    }

    function remember(bindingId, expiresAt) {
        try {
            const list = readMarker().filter(item => item.binding_id !== bindingId);
            list.push({ binding_id: bindingId, expires_at: expiresAt });
            localStorage.setItem(markerKey, JSON.stringify(list));
        } catch (_) {}
    }
    // One-time migration: earlier versions kept the emergency credential in IndexedDB. Keep only
    // each entry's binding ID and expiry as the non-secret marker, then delete that database.
    function migrateOldCopies() {
        return new Promise(resolve => {
            const name = 'saml-emergency-credentials-v1';
            if (!window.indexedDB) return resolve();
            let request;
            try {
                request = indexedDB.open(name, 1);
            } catch (_) {
                return resolve();
            }
            const done = () => {
                try {
                    indexedDB.deleteDatabase(name);
                } catch (_) {}
                resolve();
            };
            request.onupgradeneeded = event => {
                // No old database: do not create one.
                if (event.oldVersion === 0) request.transaction.abort();
            };
            request.onerror = request.onblocked = () => resolve();
            request.onsuccess = () => {
                const db = request.result;
                if (!db.objectStoreNames.contains('entries')) {
                    db.close();
                    return done();
                }
                const transaction = db.transaction('entries', 'readonly');
                const all = transaction.objectStore('entries').getAll();
                transaction.oncomplete = () => {
                    db.close();
                    for (const entry of all.result || [])
                        if (entry && typeof entry.binding_id === 'string')
                            remember(entry.binding_id, entry.expires_at);
                    done();
                };
                transaction.onerror = transaction.onabort = () => {
                    db.close();
                    done();
                };
            };
        });
    }
    async function isActive(bindingId) {
        try {
            const value = await send('login-status', { binding_id: bindingId });
            return value.active === true;
        } catch (_) {
            return false;
        }
    }

    // Binding IDs of the active keys set up in this browser; stale marker entries are dropped.
    let activeBindings = [];
    async function hasActiveKey() {
        const now = Date.now();
        const stale = [];
        activeBindings = [];
        for (const item of readMarker()) {
            if (typeof item.expires_at === 'number' && item.expires_at * 1000 <= now) {
                stale.push(item.binding_id);
            } else if (await isActive(item.binding_id)) {
                activeBindings.push(item.binding_id);
            } else {
                stale.push(item.binding_id);
            }
        }
        if (stale.length) forget(stale);
        return activeBindings.length > 0;
    }

    async function login() {
        // Only the non-secret binding IDs are sent. The server names those keys' passkeys in the
        // challenge, so the browser goes straight to the right one instead of listing every
        // passkey it holds for this site.
        const pending = await send('login-options', { binding_ids: activeBindings });
        const options = pending.publicKey;
        options.challenge = bytes(options.challenge);
        options.allowCredentials = (options.allowCredentials || []).map(item => ({
            type: item.type || 'public-key',
            id: bytes(item.id),
        }));
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
    function button(label) {
        const element = document.createElement('button');
        element.type = 'button';
        element.className = 'btn btn-default login-alt-button';
        element.textContent = label;
        element.addEventListener('click', async () => {
            element.disabled = true;
            show('Confirm with your security key or passkey...', 'busy');
            try {
                await login();
            } catch (error) {
                show(
                    error.name === 'NotAllowedError' && error.webauthnMs < 1500
                        ? 'The browser refused the key check without showing a prompt (' +
                          error.name + ': ' + error.message + '). Check that this browser can use ' +
                          'your passkey or security key.'
                        : error.name === 'NotAllowedError'
                        ? 'Key check cancelled, timed out, or no emergency passkey was found on this device. Try again when your key is ready.'
                        : error.message || 'Emergency login failed.',
                    'error',
                );
                element.disabled = false;
            }
        });
        return element;
    }

    (async function () {
        try {
            await migrateOldCopies();
            if (!(await hasActiveKey())) {
                proceed();
                return;
            }
            actions.replaceChildren(button('Emergency login'));
            card.hidden = false;
        } catch (_) {
            // Any failure keeps the card hidden; normal login is unaffected.
            proceed();
        }
    })();
})();