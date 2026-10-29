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
    // The browser keeps no emergency credential. A non-secret marker lists the keys set up in
    // this browser (binding ID and expiry) so the sign-in page knows when to offer emergency
    // login. The sign-in page and My Page migrate and delete the IndexedDB copy older versions kept.
    const markerKey = 'saml-emergency-login-v1';
    function readMarker() {
        try {
            const list = JSON.parse(localStorage.getItem(markerKey) || '[]');
            return Array.isArray(list) ? list.filter(item => item && typeof item.binding_id === 'string') : [];
        } catch (_) {
            return [];
        }
    }
    function forgetBinding(bindingId) {
        try {
            const list = readMarker().filter(item => item.binding_id !== bindingId);
            if (list.length) localStorage.setItem(markerKey, JSON.stringify(list));
            else localStorage.removeItem(markerKey);
        } catch (_) {}
    }
    function control(label, work, variant) {
        const button = element('button', variant || 'secondary', label);
        button.type = 'button';
        button.addEventListener('click', action(work));
        return button;
    }
    // Destructive actions confirm inline: the first click arms the button, a second click
    // within a few seconds runs it. No native dialog, which some browsers suppress.
    function confirmControl(label, prompt, work) {
        const button = element('button', 'danger', label);
        button.type = 'button';
        let armed = false;
        let timer = null;
        const disarm = () => {
            armed = false;
            button.textContent = label;
        };
        button.addEventListener(
            'click',
            action(async () => {
                if (!armed) {
                    armed = true;
                    button.textContent = 'Confirm removal';
                    show(prompt + ' Select "Confirm removal" to continue.', 'info');
                    timer = setTimeout(disarm, 8000);
                    return;
                }
                clearTimeout(timer);
                disarm();
                await work();
            }),
        );
        return button;
    }
    const statusLabels = {
        pending: 'Not activated',
        active: 'Active',
        replaced: 'Replaced',
        blocked: 'Blocked',
        expired: 'Expired',
    };
    async function displayKeys() {
        const list = document.getElementById('saved-keys');
        if (!list) return;
        const state = page.dataset.mode === 'prepare' ? await send('status') : null;
        list.replaceChildren();
        if (!state) return;
        // Keys belong to the account on the server; show each key's newest credential.
        const newest = new Map();
        for (const item of state.credentials || []) {
            const current = newest.get(item.binding_id);
            if (!current || item.expires_at > current.expires_at) newest.set(item.binding_id, item);
        }
        const here = new Set(readMarker().map(item => item.binding_id));
        for (const entry of newest.values()) {
            const row = element('li', 'key');
            const head = element('div', 'key-head');
            head.append(
                element('span', 'key-name', 'Key \u2026' + entry.binding_id.slice(-6)),
                element('span', 'badge ' + entry.status, statusLabels[entry.status] || entry.status),
            );
            if (here.has(entry.binding_id)) head.append(element('span', 'badge active', 'This browser'));
            if (entry.renew_soon && entry.status === 'active')
                head.append(element('span', 'badge pending', 'Renew soon'));
            row.append(head);
            row.append(
                element(
                    'span',
                    'key-meta',
                    (entry.status === 'expired' ? 'Expired ' : 'Expires ') +
                        new Date(entry.expires_at * 1000).toLocaleString(),
                ),
            );
            const id = element('span', 'key-meta', 'Binding ID: ');
            id.append(element('code', null, entry.binding_id));
            row.append(id);
            const actions = element('div', 'actions');
            actions.append(
                confirmControl(
                    'Remove key',
                    'Remove key \u2026' + entry.binding_id.slice(-6) + ' and end its emergency sessions?',
                    async () => {
                        await send('remove', { binding_id: entry.binding_id });
                        forgetBinding(entry.binding_id);
                        show('Key removed. Failed issuer reports remain queued and are retried.', 'success');
                        await displayKeys();
                    },
                ),
            );
            row.append(actions);
            list.append(row);
        }
        if (!list.children.length)
            list.append(
                element('li', 'empty', 'No emergency keys are registered for your account. Set one up on My Page.'),
            );
    }
    connect('exit', async () => {
        const result = await send('logout');
        location.assign(result.redirect);
    });
    if (page.dataset.mode === 'prepare') action(displayKeys)();
})();
