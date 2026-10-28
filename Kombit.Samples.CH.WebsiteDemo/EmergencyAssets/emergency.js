(function () {
    'use strict';
    const page = document.getElementById('saml-emergency');
    if (!page) return;
    const token = document.getElementById('csrf').value;
    const show = (text, tone) => {
        const status = document.getElementById('status');
        status.dataset.tone = tone || 'info';
        status.textContent = text;
    };
    const messages = {
        csrf_or_origin_rejected: 'The request was rejected. Reload the page and try again.',
        https_origin_required: 'Emergency access requires the configured HTTPS address.',
        key_proof_rejected: 'The key check was rejected.',
        local_policy_denied: 'Local policy does not allow this action.',
        new_normal_login_required:
            'A new normal login is required. Use "Get a new normal login" first.',
        normal_login_required: 'A normal login is required for this action.',
        proof_expired: 'The key check took too long. Try again.',
        registration_expired: 'Registration took too long. Try again.',
        state_changed_retry: 'The state changed while working. Try again.',
    };
    function describe(code) {
        if (messages[code]) return messages[code];
        if (/^[a-z_]+$/.test(code)) {
            const words = code.replace(/_/g, ' ');
            return words.charAt(0).toUpperCase() + words.slice(1) + '.';
        }
        return code;
    }
    function element(tag, className, content) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (content != null) node.textContent = content;
        return node;
    }

    const traceKey = 'saml-emergency-issuer-results-v1';
    let callHistory = [];
    try {
        const saved = JSON.parse(sessionStorage.getItem(traceKey) || '[]');
        if (Array.isArray(saved))
            callHistory = saved
                .slice(-40)
                .filter(x => typeof x === 'string')
                .map(x => x.slice(0, 600));
    } catch (_) {}
    function renderIssuerCalls() {
        const list = document.getElementById('issuer-call-results');
        if (!list) return;
        list.replaceChildren();
        for (const text of callHistory.slice().reverse()) {
            const item = document.createElement('li');
            item.textContent = text;
            list.append(item);
        }
        if (!callHistory.length) {
            const item = document.createElement('li');
            item.textContent =
                'No calls recorded in this tab yet. Open the preparation page, or prepare, renew, or remove a key to see Identify results.';
            list.append(item);
        }
    }
    function recordIssuerCalls(response) {
        try {
            const header = response.headers.get('X-Emergency-Issuer-Calls');
            const stamp = new Date().toLocaleTimeString();
            if (!header)
                callHistory.push(
                    stamp +
                        ' \u2014 No issuer diagnostics received (older server or request rejected before the handler).',
                );
            else {
                const calls = JSON.parse(atob(header));
                if (!Array.isArray(calls)) return;
                if (!calls.length)
                    callHistory.push(
                        stamp +
                            ' \u2014 Local request: HTTP ' +
                            response.status +
                            '; no Identify endpoint called.',
                    );
                for (const call of calls.slice(-8))
                    callHistory.push(
                        (
                            stamp +
                            ' \u2014 ' +
                            call.method +
                            ' ' +
                            call.endpoint +
                            ' \u2014 ' +
                            (call.status == null ? 'no HTTP status' : 'HTTP ' + call.status) +
                            ' \u2014 ' +
                            call.milliseconds +
                            ' ms \u2014 ' +
                            call.summary
                        ).slice(0, 600),
                    );
            }
            callHistory = callHistory.slice(-40);
            try {
                sessionStorage.setItem(traceKey, JSON.stringify(callHistory));
            } catch (_) {}
            renderIssuerCalls();
        } catch (_) {
            /* Diagnostics must never interrupt authentication. */
        }
    }
    const clearTrace = document.getElementById('clear-issuer-diagnostics');
    if (clearTrace)
        clearTrace.addEventListener('click', () => {
            callHistory = [];
            try {
                sessionStorage.removeItem(traceKey);
            } catch (_) {}
            renderIssuerCalls();
        });
    renderIssuerCalls();


    async function send(operation, values) {
        const response = await fetch(page.dataset.api + '?op=' + encodeURIComponent(operation), {
            method: 'POST',
            credentials: 'same-origin',
            redirect: 'error',
            headers: { 'Content-Type': 'application/json', 'X-Emergency-CSRF': token },
            body: JSON.stringify(values || {}),
        });
        recordIssuerCalls(response);
        const value = await response.json();
        if (!response.ok) {
            const code = value.error || 'Request failed';
            const message = typeof value.message === 'string' ? value.message : describe(code);
            const reference =
                typeof value.reference_id === 'string'
                    ? value.reference_id
                    : response.headers.get('X-Emergency-Reference');
            throw new Error(
                message +
                    ' (Error: ' +
                    code +
                    '; HTTP ' +
                    response.status +
                    (reference ? '; Reference: ' + reference : '') +
                    ')',
            );
        }
        return value;
    }
    function action(operation) {
        return async function (event) {
            if (event) event.preventDefault();
            try {
                show('Working\u2026', 'busy');
                const status = document.getElementById('status');
                await operation();
                if (status.dataset.tone === 'busy') show('');
            } catch (error) {
                show(
                    error.name === 'NotAllowedError'
                        ? 'Key check cancelled. The credential is not ready.'
                        : error.message || 'Operation failed.',
                    'error',
                );
            }
        };
    }
    function connect(id, operation) {
        const element = document.getElementById(id);
        if (element) element.addEventListener('click', action(operation));
    }
    async function deleteStoredBinding(bindingId) {
        const db = await new Promise((resolve, reject) => {
            const request = indexedDB.open('saml-emergency-credentials-v1', 1);
            request.onupgradeneeded = () => request.result.createObjectStore('entries', { keyPath: 'ec_id' });
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(new Error('Browser storage is unavailable.'));
        });
        try {
            await new Promise((resolve, reject) => {
                const transaction = db.transaction('entries', 'readwrite');
                const cursor = transaction.objectStore('entries').openCursor();
                cursor.onsuccess = () => {
                    const item = cursor.result;
                    if (!item) return;
                    if (item.value.binding_id === bindingId) item.delete();
                    item.continue();
                };
                transaction.oncomplete = resolve;
                transaction.onerror = transaction.onabort = () => reject(new Error('Key removed from the server, but browser cleanup failed. Retry browser cleanup before using emergency login.'));
            });
        } finally { db.close(); }
    }

    async function storage(record) {
        const database = await new Promise((resolve, reject) => {
            const request = indexedDB.open('saml-emergency-credentials-v1', 1);
            request.onupgradeneeded = () =>
                request.result.createObjectStore('entries', { keyPath: 'ec_id' });
            request.onerror = () => reject(new Error('Browser storage is unavailable.'));
            request.onsuccess = () => resolve(request.result);
        });
        try {
            return await new Promise((resolve, reject) => {
                const transaction = database.transaction(
                    'entries',
                    record ? 'readwrite' : 'readonly',
                );
                const entries = transaction.objectStore('entries');
                const request = record ? entries.put(record) : entries.getAll();
                transaction.oncomplete = () => resolve(request.result);
                transaction.onerror = transaction.onabort = () =>
                    reject(new Error('Storage failed. Emergency preparation is incomplete.'));
            });
        } finally {
            database.close();
        }
    }
    // Setup and renewal run on My Page. Here a stored pending credential can be finished
    // without a second key check: the server activates it after browser read-back.
    async function activateStored(entry) {
        await send('activate-stored', { emergency_credential: entry.emergency_credential });
        show('Ready. This browser can use emergency login from the sign-in page.', 'success');
        await displayKeys();
    }
    function control(label, work, variant) {
        const button = element('button', variant || 'secondary', label);
        button.type = 'button';
        button.addEventListener('click', action(work));
        return button;
    }
    const statusLabels = {
        pending: 'Setup unfinished',
        active: 'Active',
        replaced: 'Replaced',
        blocked: 'Blocked',
        expired: 'Expired',
    };
    async function displayKeys() {
        const list = document.getElementById('saved-keys');
        if (!list) return;
        const saved = await storage();
        const state = page.dataset.mode === 'prepare' ? await send('status') : null;
        list.replaceChildren();
        for (const entry of saved) {
            const current = state && state.credentials.find(item => item.ec_id === entry.ec_id);
            if (state && !current) continue;
            const expired = entry.expires_at * 1000 <= Date.now();
            const status = current ? current.status : 'active';
            const row = element('li', 'key');
            const head = element('div', 'key-head');
            head.append(
                element('span', 'key-name', 'Key \u2026' + entry.binding_id.slice(-6)),
                element(
                    'span',
                    'badge ' + status,
                    statusLabels[status] || (status === 'stored' ? 'Stored' : status),
                ),
            );
            if (current && current.renew_soon && status === 'active')
                head.append(element('span', 'badge pending', 'Renew soon'));
            row.append(head);
            row.append(
                element(
                    'span',
                    'key-meta',
                    (expired ? 'Expired ' : 'Expires ') +
                        new Date(entry.expires_at * 1000).toLocaleString() +
                        (state || expired ? '' : ' \u00b7 checked by the server on use'),
                ),
            );
            const actions = element('div', 'actions');
            if (state) {
                if (current.status === 'pending')
                    actions.append(
                        control('Finish setup', () => activateStored(entry), 'primary'),
                    );
                actions.append(
                    control(
                        'Remove key locally',
                        async () => {
                            if (!confirm('Remove key \u2026' + entry.binding_id.slice(-6) + '?')) return;
                            await send('remove', { binding_id: entry.binding_id });
                            await deleteStoredBinding(entry.binding_id);
                            show(
                                'Key removed from this browser and the local registry. Failed issuer reports remain queued.',
                                'success',
                            );
                            await displayKeys();
                        },
                        'danger',
                    ),
                );
                const id = element('span', 'key-meta', 'Binding ID: ');
                id.append(element('code', null, entry.binding_id));
                row.append(id);
            }
            if (actions.children.length) row.append(actions);
            list.append(row);
        }
        // Status belongs to the authenticated account, even after browser storage is cleared.
        if (state) {
            const missing = new Map();
            for (const entry of state.credentials) {
                if (!saved.some(record => record.binding_id === entry.binding_id && state.credentials.some(item => item.ec_id === record.ec_id))) missing.set(entry.binding_id, entry);
            }
            for (const entry of missing.values()) {
                const row = element('li', 'key');
                row.append(element('span', 'key-name', 'Key \u2026' + entry.binding_id.slice(-6)),
                    element('p', 'key-meta', 'Browser copy missing. Remove this registration before preparing the same authenticator again. This also ends its emergency sessions in other browsers.'));
                row.append(control('Remove key locally', async () => {
                    if (!confirm('Remove registration for key \u2026' + entry.binding_id.slice(-6) + ' and end its emergency sessions?')) return;
                    await send('remove', { binding_id: entry.binding_id });
                    await deleteStoredBinding(entry.binding_id);
                    show('Registration removed locally. If Identify is unavailable, its revocation is queued; wait for it to synchronize before preparing this key again.', 'success');
                    await displayKeys();
                }, 'danger'));
                list.append(row);
            }
        }
        if (!list.children.length)
            list.append(
                element(
                    'li',
                    'empty',
                    'This browser has no matching prepared credential. Use normal login to prepare.',
                ),
            );
    }
    connect('exit', async () => {
        const result = await send('logout');
        location.assign(result.redirect);
    });
    if (page.dataset.mode === 'prepare') action(displayKeys)();
})();
