(function () {
    'use strict';
    // Emergency access widget: a card on My Page, or an inline button on the home page
    // (data-layout="inline", label from data-setup-label). After a normal login it:
    // - offers one-click setup for this browser (one WebAuthn registration prompt),
    // - renews any of the account's keys silently once half their lifetime has passed.
    // The browser stores no emergency credential: the server activates it at registration and
    // emergency login uses the discoverable passkey itself. Only a non-secret marker (binding ID
    // and expiry) is kept so the sign-in page knows this browser has a key.
    const card = document.getElementById('emergency-setup');
    if (!card) return;
    const text = document.getElementById('emergency-setup-text');
    const actions = document.getElementById('emergency-setup-actions');
    const status = document.getElementById('emergency-setup-status');
    const inline = card.dataset.layout === 'inline';
    const markerKey = 'saml-emergency-login-v1';

    const messages = {
        csrf_or_origin_rejected: 'The request was rejected. Reload the page and try again.',
        key_conflict: 'This key is already registered. Remove it under Manage keys first.',
        new_normal_login_required: 'Sign in again, then set up emergency access.',
        registration_expired: 'Setup took too long. Try again.',
    };

    function show(message, tone) {
        status.textContent = message || '';
        status.dataset.tone = tone || 'info';
        status.hidden = !message;
    }

    // The inline layout shows the short text (or none) next to its buttons.
    function describe(lines, buttons, short) {
        text.textContent = inline ? short || '' : lines;
        actions.replaceChildren(...(buttons || []));
    }

    function link(label, href, variant) {
        const element = document.createElement('a');
        element.className = 'btn ' + (variant || 'btn-default');
        element.href = href;
        element.textContent = label;
        return element;
    }

    function date(seconds) {
        return new Date(seconds * 1000).toLocaleDateString(undefined, {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
        });
    }

    function bytes(value) {
        const base64 =
            value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4);
        return Uint8Array.from(atob(base64), character => character.charCodeAt(0));
    }

    function encode(value) {
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
                (messages[code] || 'Emergency access setup failed.') +
                    ' (Error: ' + code + '; HTTP ' + response.status +
                    (reference ? '; Reference: ' + reference : '') + ')',
            );
            error.code = code;
            throw error;
        }
        return value;
    }

    function readMarker() {
        try {
            const list = JSON.parse(localStorage.getItem(markerKey) || '[]');
            return Array.isArray(list) ? list.filter(item => item && typeof item.binding_id === 'string') : [];
        } catch (_) {
            return [];
        }
    }

    function writeMarker(list) {
        try {
            if (list.length) localStorage.setItem(markerKey, JSON.stringify(list));
            else localStorage.removeItem(markerKey);
        } catch (_) {
            // Without the marker the sign-in page just does not offer emergency login here.
        }
    }

    function remember(bindingId, expiresAt) {
        const list = readMarker().filter(item => item.binding_id !== bindingId);
        list.push({ binding_id: bindingId, expires_at: expiresAt });
        writeMarker(list);
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
    async function setUp() {
        let pending;
        try {
            pending = await send('enroll');
            const options = pending.publicKey;
            options.challenge = bytes(options.challenge);
            options.user.id = bytes(options.user.id);
            (options.excludeCredentials || []).forEach(key => (key.id = bytes(key.id)));
            // Emergency login names no key: the passkey must be discoverable, and user
            // verification is required because the passkey is then the only factor.
            options.authenticatorSelection = Object.assign({}, options.authenticatorSelection, {
                residentKey: 'required',
                requireResidentKey: true,
                userVerification: 'required',
            });            applyAuthenticator(options, 'create');
            const started = Date.now();
            let key;
            try {
                key = await navigator.credentials.create({ publicKey: options });
            } catch (error) {
                // Keep what the browser was asked for, so an instant refusal can be explained.
                error.webauthnMs = Date.now() - started;
                console.warn('Emergency setup: the browser rejected the registration request.', {
                    name: error.name,
                    message: error.message,
                    afterMs: error.webauthnMs,
                    hints: options.hints || null,
                    authenticatorSelection: options.authenticatorSelection,
                });
                throw error;
            }
            const transports = key.response.getTransports ? key.response.getTransports() : [];
            const ready = await send('enroll-complete', {
                id: pending.enrollment_id,
                credential: {
                    id: key.id,
                    rawId: encode(key.rawId),
                    type: key.type,
                    clientExtensionResults: key.getClientExtensionResults(),
                    response: {
                        clientDataJSON: encode(key.response.clientDataJSON),
                        attestationObject: encode(key.response.attestationObject),
                        transports,
                    },
                },
            });
            pending = null;
            // The server has activated the credential; remember only that this browser has a key.
            remember(ready.binding_id, ready.expires_at);
        } finally {
            if (pending) {
                try {
                    await send('enroll-cancel', { id: pending.enrollment_id });
                } catch (_) {}
            }
        }
    }

    function setupButton() {
        const element = document.createElement('button');
        element.type = 'button';
        element.className = inline ? 'btn btn-default' : 'btn btn-primary';
        element.textContent = card.dataset.setupLabel || 'Set up emergency access';
        element.addEventListener('click', async () => {
            element.disabled = true;
            show('Follow your browser\'s prompt to register your security key or passkey...', 'busy');
            try {
                await setUp();
                show('');
                await refresh(false);
            } catch (error) {
                element.disabled = false;
                show(
                    error.name === 'NotAllowedError' && error.webauthnMs < 1500
                        ? 'The browser refused to register a key without showing a prompt (' +
                          error.name + ': ' + error.message + '). Check that this browser can use ' +
                          'your passkey or security key, then try again.'
                        : error.name === 'NotAllowedError'
                        ? 'Setup was cancelled or timed out. Try again when your key is ready.'
                        : error.name === 'InvalidStateError'
                        ? 'This key is already registered. Remove it under Manage keys first.'
                        : error.message || 'Emergency access setup failed.',
                    'error',
                );
            }
        });
        return element;
    }

    async function refresh(allowRenewal) {
        const state = await send('status');
        const mine = state.credentials || [];
        const newest = new Map();
        for (const item of mine) {
            if (item.status !== 'active') continue;
            const current = newest.get(item.binding_id);
            if (!current || item.expires_at > current.expires_at) newest.set(item.binding_id, item);
        }

        // Renewal needs no browser copy: renew any due key of this account.
        const due = [...newest.values()].find(item => item.renew_due);
        if (allowRenewal && due && state.can_prepare) {
            try {
                const renewed = await send('renew', { binding_id: due.binding_id });
                if (readMarker().some(item => item.binding_id === renewed.binding_id))
                    remember(renewed.binding_id, renewed.expires_at);
                return refresh(false);
            } catch (_) {
                // Renewal is retried after the next normal login; the current key stays valid.
            }
        }

        // Keep the marker in step with this account's keys; entries of other accounts stay.
        const accountKeys = new Set(mine.map(item => item.binding_id));
        writeMarker(
            readMarker()
                .filter(item => !accountKeys.has(item.binding_id) || newest.has(item.binding_id))
                .map(item =>
                    newest.has(item.binding_id)
                        ? { binding_id: item.binding_id, expires_at: newest.get(item.binding_id).expires_at }
                        : item,
                ),
        );
        const here = readMarker().filter(item => newest.has(item.binding_id));
        const manage = link('Manage keys', card.dataset.manage, inline ? 'btn-link' : 'btn-default');
        if (here.length) {
            const latest = Math.max(...here.map(item => item.expires_at));
            describe(
                'Emergency access is ready on this browser until ' + date(latest) +
                    '. It renews automatically when you sign in normally.',
                [manage],
                'Emergency access ready until ' + date(latest) + '.',
            );
            card.dataset.state = 'ready';
            return;
        }

        card.dataset.state = 'setup';
        const elsewhere = newest.size > 0;
        if (!state.can_prepare) {
            describe(
                'Sign in again to set up emergency access for this browser.',
                [
                    inline
                        ? link('Sign in again to prepare emergency access', card.dataset.login)
                        : link('Sign in again', card.dataset.login, 'btn-primary'),
                ].concat(elsewhere ? [manage] : []),
            );
            return;
        }
        describe(
            elsewhere
                ? 'Emergency access is set up for your account in another browser or device. Set it ' +
                      'up here too if you want emergency login from this browser.'
                : 'Set up emergency access so you can still sign in from this browser if your identity ' +
                      'provider is unavailable. Your browser asks for your security key or passkey once.',
            [setupButton()].concat(elsewhere ? [manage] : []),
        );
    }
    if (!window.PublicKeyCredential || !window.fetch) {
        describe(
            'This browser does not support security keys or passkeys, so emergency access cannot be set up here.',
            [],
            'This browser cannot use emergency access.',
        );
        return;
    }
    migrateOldCopies().then(() => refresh(true)).catch(error => {
        describe('Emergency access status is unavailable right now.', [], 'Emergency access status is unavailable.');
        show(error.message, 'error');
    });
})();
