(function () {
    'use strict';
    const page = document.getElementById('saml-emergency');
    if (!page) return;
    const token = document.getElementById('csrf').value;
    const show = text => {
        document.getElementById('status').textContent = text;
    };

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
                'No calls recorded in this tab yet. Perform preparation, renewal, removal, or operator synchronization to see Identify results.';
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
                        ' — No issuer diagnostics received (older server or request rejected before the handler).',
                );
            else {
                const calls = JSON.parse(atob(header));
                if (!Array.isArray(calls)) return;
                if (!calls.length)
                    callHistory.push(
                        stamp +
                            ' — Local request: HTTP ' +
                            response.status +
                            '; no Identify endpoint called.',
                    );
                for (const call of calls.slice(-8))
                    callHistory.push(
                        (
                            stamp +
                            ' — ' +
                            call.method +
                            ' ' +
                            call.endpoint +
                            ' — ' +
                            (call.status == null ? 'no HTTP status' : 'HTTP ' + call.status) +
                            ' — ' +
                            call.milliseconds +
                            ' ms — ' +
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
        if (!response.ok) throw new Error(value.error || 'Request failed');
        return value;
    }
    function action(operation) {
        return async function (event) {
            if (event) event.preventDefault();
            try {
                show('Working…');
                await operation();
            } catch (error) {
                show(
                    error.name === 'NotAllowedError'
                        ? 'Key check cancelled. The credential is not ready.'
                        : error.message || 'Operation failed.',
                );
            }
        };
    }
    function connect(id, operation, type) {
        const element = document.getElementById(id);
        if (element) element.addEventListener(type || 'click', action(operation));
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
    async function prove(entry, login) {
        const kind = login ? 'login' : 'activate';
        const pending = await send(kind + '-options', {
            emergency_credential: entry.emergency_credential,
        });
        const options = pending.publicKey;
        options.challenge = bytes(options.challenge);
        options.allowCredentials.forEach(key => (key.id = bytes(key.id)));
        const key = await navigator.credentials.get({ publicKey: options });
        const response = key.response;
        const result = await send(kind + '-complete', {
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
        if (login) {
            location.assign(result.redirect);
        } else {
            show('Ready. This browser and key can log in while local acceptance is on.');
            await displayKeys();
        }
    }
    async function keep(entry) {
        const persistent =
            navigator.storage && navigator.storage.persist
                ? await navigator.storage.persist()
                : false;
        document.getElementById('storage-note').textContent = persistent
            ? 'Persistent storage granted. Clearing site data still removes preparation.'
            : 'Persistent storage was not granted. Cleanup or eviction can remove preparation.';
        await storage(entry);
        const saved = (await storage()).find(item => item.ec_id === entry.ec_id);
        if (!saved || saved.emergency_credential !== entry.emergency_credential)
            throw new Error('Storage read-back failed. The credential is not ready.');
        show('Stored, pending activation. Check your key again.');
        await prove(saved, false);
    }
    connect('register', async () => {
        let pending;
        try {
            pending = await send('enroll');
            const options = pending.publicKey;
            options.challenge = bytes(options.challenge);
            options.user.id = bytes(options.user.id);
            (options.excludeCredentials || []).forEach(key => (key.id = bytes(key.id)));
            const key = await navigator.credentials.create({ publicKey: options });
            const entry = await send('enroll-complete', {
                id: pending.enrollment_id,
                credential: {
                    id: key.id,
                    rawId: text(key.rawId),
                    type: key.type,
                    clientExtensionResults: key.getClientExtensionResults(),
                    response: {
                        clientDataJSON: text(key.response.clientDataJSON),
                        attestationObject: text(key.response.attestationObject),
                        transports: key.response.getTransports ? key.response.getTransports() : [],
                    },
                },
            });
            pending = null;
            await keep(entry);
        } finally {
            if (pending) {
                try {
                    await send('enroll-cancel', { id: pending.enrollment_id });
                } catch (_) {}
            }
        }
    });
    function control(label, work) {
        const button = document.createElement('button');
        button.type = 'button';
        button.textContent = label;
        button.addEventListener('click', action(work));
        return button;
    }
    async function displayKeys() {
        const list = document.getElementById('saved-keys');
        if (!list) return;
        const saved = await storage();
        const state = page.dataset.mode === 'prepare' ? await send('status') : null;
        list.replaceChildren();
        for (const entry of saved) {
            const current = state && state.credentials.find(item => item.ec_id === entry.ec_id);
            if (state && !current) continue;
            const row = document.createElement('li');
            row.textContent =
                'Key ' +
                entry.binding_id.slice(-6) +
                ' — ' +
                (current ? current.status : 'stored; checked by the server on use') +
                ' — expires ' +
                new Date(entry.expires_at * 1000).toLocaleString() +
                ' ';
            if (!state) {
                if (entry.expires_at * 1000 > Date.now())
                    row.append(control('Log in with this key', () => prove(entry, true)));
            } else {
                if (current.status === 'pending')
                    row.append(control('Confirm stored credential', () => prove(entry, false)));
                if (current.status === 'active' && state.can_prepare)
                    row.append(
                        control('Renew', async () =>
                            keep(await send('renew', { binding_id: entry.binding_id })),
                        ),
                    );
                row.append(
                    control('Remove key locally', async () => {
                        await send('remove', { binding_id: entry.binding_id });
                        show('Key blocked locally. Failed issuer reports remain queued.');
                        await displayKeys();
                    }),
                );
                const id = document.createElement('p');
                id.textContent = 'Binding ID: ' + entry.binding_id;
                row.append(id);
            }
            list.append(row);
        }
        if (!list.children.length) {
            const empty = document.createElement('li');
            empty.textContent =
                'This browser has no matching prepared credential. Use normal login to prepare.';
            list.append(empty);
        }
    }
    async function operatorState() {
        const state = await send('operator-status');
        document.getElementById('operator-panel').hidden = false;
        document.getElementById('operator-status').textContent =
            'Acceptance: ' +
            (state.accepting ? 'on' : 'off') +
            '. Last successful sync: ' +
            (state.last_poll ? new Date(state.last_poll * 1000).toLocaleString() : 'never') +
            '. Queued removals: ' +
            state.queued_removals;
        const list = document.getElementById('events');
        list.replaceChildren();
        state.audit
            .slice()
            .reverse()
            .forEach(value => {
                const row = document.createElement('li');
                row.textContent = value;
                list.append(row);
            });
    }
    connect(
        'operator-form',
        async () => {
            const field = document.getElementById('operator-key');
            const secret = field.value;
            field.value = '';
            await send('operator-login', { secret });
            location.reload();
        },
        'submit',
    );
    connect('enable', async () => {
        await send('acceptance', {
            enabled: true,
            minutes: Number(document.getElementById('duration').value),
        });
        await operatorState();
        show('Acceptance enabled.');
    });
    connect('disable', async () => {
        await send('acceptance', { enabled: false, minutes: 0 });
        await operatorState();
        show('Acceptance stopped. Existing emergency sessions are invalid.');
    });
    connect('block', async () => {
        await send('block', {
            binding_id: document.getElementById('binding-id').value,
            whole_account: document.getElementById('block-account').checked,
        });
        await operatorState();
        show('Local block applied.');
    });
    connect('sync', async () => {
        await send('poll');
        await operatorState();
        show('Online synchronization completed.');
    });
    connect('operator-exit', async () => {
        await send('operator-logout');
        location.reload();
    });
    connect('exit', async () => {
        const result = await send('logout');
        location.assign(result.redirect);
    });
    if (
        page.dataset.mode === 'prepare' ||
        (page.dataset.mode === 'login' && page.dataset.accepting === 'true')
    )
        action(displayKeys)();
    if (page.dataset.mode === 'operator' && !document.getElementById('operator-panel').hidden)
        action(operatorState)();
})();
