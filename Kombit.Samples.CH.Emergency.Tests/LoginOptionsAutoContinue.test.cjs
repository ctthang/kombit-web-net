// Run with node LoginOptionsAutoContinue.test.cjs. Uses only Node built-ins.
// Runs the real login-options.js against a fake browser to check when the sign-in page
// continues to the single IdP and when it shows the emergency card.
const fs = require('fs'), vm = require('vm'), path = require('node:path'), assert = require('node:assert/strict');
const source = fs.readFileSync(
    path.resolve(__dirname, '../Kombit.Samples.CH.WebsiteDemo/EmergencyAssets/login-options.js'),
    'utf8',
);

function element() {
    return { hidden: true, dataset: {}, textContent: '', children: [], replaceChildren(...c) { this.children = c; }, querySelectorAll: () => [] };
}

// A fake IndexedDB holding the given entries, or no database at all when entries is null.
function fakeIndexedDb(entries) {
    return {
        open() {
            const request = { result: null, transaction: { abort() {} } };
            setTimeout(() => {
                if (entries === null) {
                    request.onupgradeneeded({ oldVersion: 0 });
                    request.onerror();
                    return;
                }
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

async function run({ continueUrl, entries, active, webauthn = true }) {
    const card = element();
    card.dataset = { api: '/EmergencyApi.ashx', csrf: 'token', authenticator: 'any' };
    if (continueUrl) card.dataset.continue = continueUrl;
    const nodes = { 'emergency-login-option': card, 'emergency-login-actions': element(), 'emergency-login-status': element() };
    const replaced = [];
    const ctx = {
        document: { getElementById: id => nodes[id] || null, createElement: () => ({ ...element(), addEventListener() {} }) },
        location: { replace: url => replaced.push(url), assign() {} },
        indexedDB: fakeIndexedDb(entries),
        PublicKeyCredential: webauthn ? function () {} : undefined,
        fetch: async () => ({ ok: true, json: async () => ({ active }), headers: { get: () => null } }),
        setTimeout, Date, Map, JSON, console, Array, Object, Uint8Array, atob, btoa, String, Error,
    };
    ctx.window = ctx;
    vm.createContext(ctx);
    vm.runInContext(source, ctx);
    await new Promise(resolve => setTimeout(resolve, 30));
    return { replaced, cardHidden: card.hidden };
}

(async () => {
    const future = Math.floor(Date.now() / 1000) + 86400;
    const key = { ec_id: 'ec', binding_id: 'binding-123456', emergency_credential: 'c', expires_at: future };
    const idp = '/login.ashx?cidp=https%3a%2f%2fidp%2f';

    let r = await run({ continueUrl: idp, entries: null, active: false });
    assert.deepEqual(r.replaced, [idp], 'no emergency database: continue to the IdP');
    assert.equal(r.cardHidden, true);

    r = await run({ continueUrl: idp, entries: [key], active: false });
    assert.deepEqual(r.replaced, [idp], 'stored key no longer active: continue to the IdP');

    r = await run({ continueUrl: idp, entries: [key], active: true, webauthn: false });
    assert.deepEqual(r.replaced, [idp], 'browser without WebAuthn: continue to the IdP');

    r = await run({ continueUrl: idp, entries: [key], active: true });
    assert.deepEqual(r.replaced, [], 'active key: stay and offer emergency login');
    assert.equal(r.cardHidden, false);

    r = await run({ continueUrl: '', entries: null, active: false });
    assert.deepEqual(r.replaced, [], 'several IdPs: never leave the chooser');

    console.log('login-options.js: auto-continue passed');
})().catch(e => { console.error(e); process.exitCode = 1; });
