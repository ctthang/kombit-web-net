(function () {
    'use strict';
    // Emergency access widget: a card on My Page, or an inline button on the home page
    // (data-layout="inline", label from data-setup-label). After a normal login it:
    // - offers one-click setup for this browser (one WebAuthn registration prompt),
    // - finishes any setup that stopped after the browser stored its credential,
    // - renews an active credential silently once half its lifetime has passed.
    // Activation needs no second key check: the server activates a credential once this
    // browser has stored and read it back; possession is proven at emergency login.
    const card = document.getElementById('emergency-setup');
    if (!card) return;
    const text = document.getElementById('emergency-setup-text');
    const actions = document.getElementById('emergency-setup-actions');
    const status = document.getElementById('emergency-setup-status');
    const inline = card.dataset.layout === 'inline';
    const database = 'saml-emergency-credentials-v1';

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
                (messages[code] || 'Emergency access setup failed.') +
                    ' (Error: ' + code + '; HTTP ' + response.status +
                    (reference ? '; Reference: ' + reference : '') + ')',
            );
            error.code = code;
            throw error;
        }
        return value;
    }

    function open() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(database, 1);
            request.onupgradeneeded = () =>
                request.result.createObjectStore('entries', { keyPath: 'ec_id' });
            request.onsuccess = () => resolve(request.result);
            request.onerror = request.onblocked = () =>
                reject(new Error('Browser storage is unavailable.'));
        });
    }

    async function withStore(mode, work) {
        const db = await open();
        try {
            return await new Promise((resolve, reject) => {
                const transaction = db.transaction('entries', mode);
                const result = work(transaction.objectStore('entries'));
                transaction.oncomplete = () => resolve(result && 'result' in result ? result.result : undefined);
                transaction.onerror = transaction.onabort = () =>
                    reject(new Error('Browser storage failed. Emergency access is not ready.'));
            });
        } finally {
            db.close();
        }
    }

    const storedEntries = () => withStore('readonly', store => store.getAll()).then(list => list || []);
    const put = entry => withStore('readwrite', store => store.put(entry));

    function removeOlderCopies(bindingId, keepId) {
        return withStore('readwrite', store => {
            const cursor = store.openCursor();
            cursor.onsuccess = () => {
                const item = cursor.result;
                if (!item) return;
                if (item.value.binding_id === bindingId && item.value.ec_id !== keepId) item.delete();
                item.continue();
            };
        });
    }

    // Store, read back, then activate on the server. No WebAuthn prompt.
    async function storeAndActivate(entry) {
        await put(entry);
        const saved = (await storedEntries()).find(item => item.ec_id === entry.ec_id);
        if (!saved || saved.emergency_credential !== entry.emergency_credential)
            throw new Error('Browser storage read-back failed. Emergency access is not ready.');
        await send('activate-stored', { emergency_credential: saved.emergency_credential });
        await removeOlderCopies(entry.binding_id, entry.ec_id);
    }

    async function setUp() {
        let pending;
        try {
            if (navigator.storage && navigator.storage.persist) await navigator.storage.persist();
            pending = await send('enroll');
            const options = pending.publicKey;
            options.challenge = bytes(options.challenge);
            options.user.id = bytes(options.user.id);
            (options.excludeCredentials || []).forEach(key => (key.id = bytes(key.id)));
            // Emergency login always names the key (allowCredentials), so a discoverable passkey is
            // not needed. Asking for a non-discoverable credential lets Windows and browsers skip
            // their "Save your passkey" step and keeps security-key slots free.
            options.authenticatorSelection = Object.assign({}, options.authenticatorSelection, {
                residentKey: 'discouraged',
                requireResidentKey: false,
            });
            applyAuthenticator(options, 'create');
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
            const entry = await send('enroll-complete', {
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
            // Kept with the browser copy so emergency login can target this key's transports.
            entry.transports = transports;
            await storeAndActivate(entry);
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
        const stored = await storedEntries();
        const byId = new Map(stored.map(entry => [entry.ec_id, entry]));
        const mine = state.credentials || [];

        // Finish a setup or renewal that stopped after the browser stored its copy.
        for (const item of mine) {
            const entry = byId.get(item.ec_id);
            if (item.status !== 'pending' || !entry) continue;
            try {
                await send('activate-stored', { emergency_credential: entry.emergency_credential });
                await removeOlderCopies(entry.binding_id, entry.ec_id);
                item.status = 'active';
            } catch (_) {}
        }

        const ready = mine.filter(item => item.status === 'active' && byId.has(item.ec_id));
        const manage = link('Manage keys', card.dataset.manage, inline ? 'btn-link' : 'btn-default');
        if (ready.length) {
            const due = ready.find(item => item.renew_due);
            if (allowRenewal && due && state.can_prepare) {
                try {
                    const renewed = await send('renew', { binding_id: due.binding_id });
                    // Renewal keeps the same key, so carry its registered transports over.
                    renewed.transports = (byId.get(due.ec_id) || {}).transports || [];
                    await storeAndActivate(renewed);
                    return refresh(false);
                } catch (_) {
                    // Renewal is retried after the next normal login; the current key stays valid.
                }
            }
            const latest = Math.max(...ready.map(item => item.expires_at));
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
        const lost = mine.some(item => item.status === 'active' && !byId.has(item.ec_id));
        if (lost) {
            describe(
                'A key is registered for your account, but this browser no longer has its copy. ' +
                    'Remove that key under Manage keys, then set up emergency access again.',
                [manage],
                'This browser lost its emergency key copy.',
            );
            return;
        }
        if (!state.can_prepare) {
            describe(
                'Sign in again to set up emergency access for this browser.',
                [
                    inline
                        ? link('Sign in again to prepare emergency access', card.dataset.login)
                        : link('Sign in again', card.dataset.login, 'btn-primary'),
                ],
            );
            return;
        }
        describe(
            'Set up emergency access so you can still sign in from this browser if your identity ' +
                'provider is unavailable. Your browser asks for your security key or passkey once.',
            [setupButton()],
        );
    }

    if (!window.PublicKeyCredential || !window.indexedDB || !window.fetch) {
        describe(
            'This browser does not support security keys or passkeys, so emergency access cannot be set up here.',
            [],
            'This browser cannot use emergency access.',
        );
        return;
    }
    refresh(true).catch(error => {
        describe('Emergency access status is unavailable right now.', [], 'Emergency access status is unavailable.');
        show(error.message, 'error');
    });
})();
