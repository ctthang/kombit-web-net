// Run with node LoginOptionsAutoContinue.test.cjs. Uses only Node built-ins.
// Runs the real login-options.js against a fake browser: when the sign-in page continues to the
// single IdP, when it shows the emergency card, and that emergency login sends no credential.
const fs = require('fs'), vm = require('vm'), path = require('node:path'), assert = require('node:assert/strict');
const source = fs.readFileSync(
    path.resolve(__dirname, '../Kombit.Samples.CH.WebsiteDemo/EmergencyAssets/login-options.js'),
    'utf8',
);
assert(!source.includes('emergency_credential'), 'the browser must not handle emergency credentials');
assert(!/\.put\(/.test(source), 'the browser must not store credentials in IndexedDB');

function element() {
    return {
        hidden: true, disabled: false, dataset: {}, textContent: '', children: [], listeners: {},
        replaceChildren(...c) { this.children = c; },
        querySelectorAll: () => [],
        addEventListener(name, fn) { this.listeners[name] = fn; },
    };
}

function storage(initial) {
    const values = new Map(Object.entries(initial || {}));
    return { getItem: k => (values.has(k) ? values.get(k) : null), setItem: (k, v) => values.set(k, String(v)), removeItem: k => values.delete(k) };
}

// Fake IndexedDB holding the old credential copies, or no database when entries is null.
const deleted = [];
function fakeIndexedDb(entries) {
    return {
        deleteDatabase: name => deleted.push(name),
        open() {
            const request = { result: null, transaction: { abort() {} } };
            setTimeout(() => {
                if (entries === null) { request.onupgradeneeded({ oldVersion: 0 }); request.onerror(); return; }
                request.result = {
                    objectStoreNames: { contains: () => true },
                    close() {},
                    transaction() {
                        const all = { result: entries };
                        const tx = { objectStore: () => ({ getAll: () => all }) };
                        setTimeout(() => tx.oncomplete());
                        return tx;
                    },
                };
                request.onsuccess();
            });
            return request;
        },
    };
}
async function run({ continueUrl, marker, active, webauthn = true, oldCopies = null }) {
    const card = element();
    card.dataset = { api: '/EmergencyApi.ashx', csrf: 'token', authenticator: 'platform' };
    if (continueUrl) card.dataset.continue = continueUrl;
    const nodes = { 'emergency-login-option': card, 'emergency-login-actions': element(), 'emergency-login-status': element() };
    const replaced = [], assigned = [], requests = [], gets = [];
    const local = storage(marker ? { 'saml-emergency-login-v1': JSON.stringify(marker) } : {});
    const ctx = {
        document: { getElementById: id => nodes[id] || null, createElement: () => element() },
        location: { replace: url => replaced.push(url), assign: url => assigned.push(url) },
        localStorage: local,
        indexedDB: fakeIndexedDb(oldCopies),
        PublicKeyCredential: webauthn ? function () {} : undefined,
        navigator: {
            credentials: {
                get: async options => {
                    gets.push(JSON.parse(JSON.stringify({ ...options.publicKey, challenge: null })));
                    const buf = new Uint8Array([1, 2, 3]).buffer;
                    return { id: 'AQID', rawId: buf, type: 'public-key', getClientExtensionResults: () => ({}), response: { clientDataJSON: buf, authenticatorData: buf, signature: buf, userHandle: buf } };
                },
            },
        },
        fetch: async (url, init) => {
            const op = new URL(url, 'https://x').searchParams.get('op');
            const body = JSON.parse(init.body);
            requests.push({ op, body });
            const value =
                op === 'login-status' ? { active: active.includes(body.binding_id) }
                : op === 'login-options' ? { transaction_id: 't1', publicKey: { challenge: 'AQID', allowCredentials: body.binding_ids.length ? [{ type: 'public-key', id: 'BAUG' }] : [], userVerification: 'required' } }
                : op === 'login-complete' ? { redirect: '/EmergencyHome.aspx' }
                : {};
            return { ok: true, json: async () => value, headers: { get: () => null } };
        },
        setTimeout, Date, Map, JSON, console, Array, Object, Uint8Array, atob, btoa, String, Error, URL,
    };
    ctx.window = ctx;
    vm.createContext(ctx);
    vm.runInContext(source, ctx);
    await new Promise(resolve => setTimeout(resolve, 30));
    return { card, nodes, replaced, assigned, requests, gets, local };
}

(async () => {
    const future = Math.floor(Date.now() / 1000) + 86400;
    const idp = '/login.ashx?cidp=https%3a%2f%2fidp%2f';

    let r = await run({ continueUrl: idp, marker: null, active: [] });
    assert.deepEqual(r.replaced, [idp], 'no marker: continue to the IdP');
    assert.equal(r.card.hidden, true);

    r = await run({ continueUrl: idp, marker: [{ binding_id: 'b1', expires_at: future }], active: [] });
    assert.deepEqual(r.replaced, [idp], 'key no longer active: continue to the IdP');
    assert.equal(r.local.getItem('saml-emergency-login-v1'), null, 'stale marker entries are dropped');

    r = await run({ continueUrl: idp, marker: [{ binding_id: 'b1', expires_at: 1 }], active: ['b1'] });
    assert.deepEqual(r.replaced, [idp], 'expired marker entry: continue to the IdP');

    r = await run({ continueUrl: idp, marker: [{ binding_id: 'b1', expires_at: future }], active: ['b1'], webauthn: false });
    assert.deepEqual(r.replaced, [idp], 'browser without WebAuthn: continue to the IdP');

    r = await run({ continueUrl: idp, marker: [{ binding_id: 'b1', expires_at: future }], active: ['b1'] });
    assert.deepEqual(r.replaced, [], 'active key: stay and offer emergency login');
    assert.equal(r.card.hidden, false);
    assert.equal(r.requests.find(q => q.op === 'login-status').body.binding_id, 'b1');

    // Clicking "Emergency login": no credential is sent; the server names the marked key's passkey.
    await r.nodes['emergency-login-actions'].children[0].listeners.click();
    const options = r.requests.find(q => q.op === 'login-options');
    assert.deepEqual(Object.keys(options.body), ['binding_ids'], 'login-options sends only binding IDs');
    assert.deepEqual([...options.body.binding_ids], ['b1']);
    assert.equal(r.gets.length, 1);
    assert.equal(r.gets[0].allowCredentials.length, 1, 'the marked key is named, so the browser skips its passkey list');
    assert.deepEqual(r.gets[0].hints, ['client-device']);
    assert.equal(r.requests.find(q => q.op === 'login-complete').body.transaction_id, 't1');
    assert.deepEqual(r.assigned, ['/EmergencyHome.aspx']);

    // Migration: an old IndexedDB copy becomes a marker (binding ID and expiry only) and is deleted.
    r = await run({ continueUrl: idp, marker: null, active: ['b9'], oldCopies: [{ ec_id: 'e9', binding_id: 'b9', expires_at: future, emergency_credential: 'secret-token' }] });
    assert.equal(r.card.hidden, false, 'migrated key: offer emergency login');
    const migrated = JSON.parse(r.local.getItem('saml-emergency-login-v1'));
    assert.deepEqual(migrated.map(m => Object.keys(m).sort().join(',')), ['binding_id,expires_at']);
    assert(!r.local.getItem('saml-emergency-login-v1').includes('secret-token'), 'the credential is not carried over');
    assert(deleted.includes('saml-emergency-credentials-v1'), 'the old database is deleted');

    r = await run({ continueUrl: '', marker: null, active: [] });    assert.deepEqual(r.replaced, [], 'several IdPs: never leave the chooser');

    console.log('login-options.js: auto-continue and discoverable login passed');
})().catch(e => { console.error(e); process.exitCode = 1; });
