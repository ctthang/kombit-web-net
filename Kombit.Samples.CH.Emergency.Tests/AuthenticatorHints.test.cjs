// Run with node AuthenticatorHints.test.cjs. Uses only Node built-ins.
// Checks how EmergencyCredential.Authenticator shapes WebAuthn options in both browser scripts.
const fs = require('fs'), vm = require('vm'), path = require('node:path'), assert = require('node:assert/strict');
const scripts = ['setup.js', 'login-options.js'].map(name =>
    path.resolve(__dirname, '../Kombit.Samples.CH.WebsiteDemo/EmergencyAssets', name),
);

function load(file, authenticator) {
    const source = fs.readFileSync(file, 'utf8');
    const start = source.indexOf('    function applyAuthenticator(');
    const end = source.indexOf('    async function send(', start);
    assert(start > 0 && end > start, 'applyAuthenticator not found in ' + file);
    const ctx = { card: { dataset: { authenticator } }, Object };
    vm.createContext(ctx);
    vm.runInContext(source.slice(start, end) + ';globalThis.apply = applyAuthenticator;', ctx);
    // Copy results out of the VM realm so deepStrictEqual compares values, not prototypes.
    return (options, ceremony) => JSON.parse(JSON.stringify(ctx.apply(options, ceremony)));
}

const createOptions = () => ({ authenticatorSelection: { userVerification: 'preferred', residentKey: 'preferred' } });
const getOptions = () => ({ allowCredentials: [{ type: 'public-key', id: 'x' }] });

for (const file of scripts) {
    const name = path.basename(file);

    for (const value of ['any', undefined, 'unknown']) {
        const apply = load(file, value);
        const created = apply(createOptions(), 'create');
        assert.deepEqual(created, createOptions(), name + ': ' + value + ' leaves registration unchanged');
        const got = apply(getOptions(), 'get');
        assert.deepEqual(got, getOptions(), name + ': ' + value + ' leaves login unchanged');
    }

    let apply = load(file, 'security-key');
    let created = apply(createOptions(), 'create');
    assert.deepEqual(created.hints, ['security-key']);
    assert.equal(created.authenticatorSelection.authenticatorAttachment, 'cross-platform');
    assert.equal(created.authenticatorSelection.userVerification, 'preferred', 'keeps server policy');
    assert.equal(created.authenticatorSelection.residentKey, 'preferred', 'keeps server policy');
    let got = apply(getOptions(), 'get');
    assert.deepEqual(got.hints, ['security-key']);
    assert.equal(got.allowCredentials[0].transports, undefined, 'login never filters transports');

    apply = load(file, 'platform');
    created = apply(createOptions(), 'create');
    assert.deepEqual(created.hints, ['client-device']);
    assert.equal(created.authenticatorSelection.authenticatorAttachment, 'platform');
    got = apply(getOptions(), 'get');
    assert.deepEqual(got.hints, ['client-device']);
    assert.equal(got.allowCredentials[0].transports, undefined, 'login never filters transports');

    console.log(name + ': authenticator hints passed');
}
