// Run with node SetupFlow.test.cjs. Uses only Node built-ins.
// Runs the real setup.js against a fake browser: setup requests a discoverable passkey with user
// verification, stores only a non-secret marker, and renews a due key without any prompt.
const fs = require('fs'), vm = require('vm'), path = require('node:path'), assert = require('node:assert/strict');
const source = fs.readFileSync(
    path.resolve(__dirname, '../Kombit.Samples.CH.WebsiteDemo/EmergencyAssets/setup.js'),
    'utf8',
);
assert(!/\.put\(/.test(source), 'the browser must not store credentials in IndexedDB');
assert(!source.includes('activate-stored'), 'activation happens on the server');

function element() {
    return {
        hidden: true, disabled: false, dataset: {}, textContent: '', children: [], listeners: {}, className: '',
        replaceChildren(...c) { this.children = c; },
        addEventListener(name, fn) { this.listeners[name] = fn; },
    };
}

function storage() {
    const values = new Map();
    return { getItem: k => (values.has(k) ? values.get(k) : null), setItem: (k, v) => values.set(k, String(v)), removeItem: k => values.delete(k), values };
}

async function run({ credentials, renewDue = false }) {
    const card = element();
    card.dataset = { api: '/EmergencyApi.ashx', csrf: 'token', authenticator: 'platform', manage: '/Emergency.aspx', login: '/login.ashx' };
    const nodes = { 'emergency-setup': card, 'emergency-setup-text': element(), 'emergency-setup-actions': element(), 'emergency-setup-status': element() };
    const requests = [], creates = [];
    const local = storage();
    let current = credentials.slice();
    const ctx = {
        document: { getElementById: id => nodes[id] || null, createElement: () => element() },
        localStorage: local,
        indexedDB: {
            deleteDatabase: name => requests.push({ op: 'deleteDatabase', body: name }),
            open() {
                const request = { transaction: { abort() {} } };
                setTimeout(() => { request.onupgradeneeded({ oldVersion: 0 }); request.onerror(); });
                return request;
            },
        },
        PublicKeyCredential: function () {},
        navigator: {
            credentials: {
                create: async options => {
                    creates.push(JSON.parse(JSON.stringify({ ...options.publicKey, challenge: null, user: null })));
                    const buf = new Uint8Array([1, 2, 3]).buffer;
                    return { id: 'AQID', rawId: buf, type: 'public-key', getClientExtensionResults: () => ({}), response: { clientDataJSON: buf, attestationObject: buf, getTransports: () => ['internal'] } };
                },
            },
        },
        fetch: async (url, init) => {
            const op = new URL(url, 'https://x').searchParams.get('op');
            const body = JSON.parse(init.body);
            requests.push({ op, body });
            let value = {};
            if (op === 'status') value = { can_prepare: true, credentials: current };
            if (op === 'enroll') value = { enrollment_id: 'e1', publicKey: { challenge: 'AQID', user: { id: 'AQID' }, authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' } } };
            if (op === 'enroll-complete' || op === 'renew') {
                value = { ready: true, binding_id: op === 'renew' ? body.binding_id : 'new-binding', ec_id: 'ec2', expires_at: 2000000000 };
                current = [{ binding_id: value.binding_id, ec_id: 'ec2', expires_at: 2000000000, status: 'active', renew_due: false }];
            }
            return { ok: true, json: async () => value, headers: { get: () => null } };
        },
        setTimeout, Date, Map, Set, JSON, console, Array, Object, Uint8Array, atob, btoa, String, Error, URL, Math,
    };
    ctx.window = ctx;
    vm.createContext(ctx);
    vm.runInContext(source, ctx);
    await new Promise(resolve => setTimeout(resolve, 30));
    return { card, nodes, requests, creates, local };
}

(async () => {
    // First setup in this browser.
    let r = await run({ credentials: [] });
    assert.equal(r.card.dataset.state, 'setup');
    assert(!r.requests.some(q => q.op === 'deleteDatabase'), 'no old database: nothing to delete');
    await r.nodes['emergency-setup-actions'].children[0].listeners.click();
    assert.equal(r.creates.length, 1, 'one registration prompt');
    assert.equal(r.creates[0].authenticatorSelection.residentKey, 'required');
    assert.equal(r.creates[0].authenticatorSelection.requireResidentKey, true);
    assert.equal(r.creates[0].authenticatorSelection.userVerification, 'required');
    assert.equal(r.creates[0].authenticatorSelection.authenticatorAttachment, 'platform');
    assert.equal(r.requests.filter(q => q.op === 'activate-stored').length, 0);
    const marker = JSON.parse(r.local.getItem('saml-emergency-login-v1'));
    assert.equal(marker.length, 1);
    assert.equal(marker[0].binding_id, 'new-binding');
    assert.deepEqual(Object.keys(marker[0]).sort(), ['binding_id', 'expires_at'], 'the marker holds no credential');
    assert.equal(r.card.dataset.state, 'ready');
    console.log('setup.js: setup passed');

    // A key set up in another browser: offer setup here too.
    r = await run({ credentials: [{ binding_id: 'elsewhere', ec_id: 'x', expires_at: 2000000000, status: 'active', renew_due: false }] });
    assert.equal(r.card.dataset.state, 'setup');
    assert.match(r.nodes['emergency-setup-text'].textContent, /another browser or device/);
    console.log('setup.js: key elsewhere passed');

    // A due key is renewed silently, without any WebAuthn prompt.
    r = await run({ credentials: [{ binding_id: 'old-binding', ec_id: 'ec1', expires_at: 1900000000, status: 'active', renew_due: true }] });
    assert.equal(r.creates.length, 0, 'no prompt for renewal');
    assert.equal(r.requests.find(q => q.op === 'renew').body.binding_id, 'old-binding');
    console.log('setup.js: silent renewal passed');
})().catch(e => { console.error(e); process.exitCode = 1; });
