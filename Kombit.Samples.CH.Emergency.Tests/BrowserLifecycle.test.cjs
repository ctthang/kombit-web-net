// Run with node BrowserLifecycle.test.cjs. Uses only Node built-ins.
// Checks the Manage keys list (displayKeys in emergency.js): keys come from the server, the
// browser stores no emergency credential, and removal also clears this browser's marker.
const fs = require('fs'), vm = require('vm'), path = require('node:path'), assert = require('node:assert/strict');

class Element {
    constructor(tag, cls, text) { this.tag = tag; this.className = cls; this.textContent = text || ''; this.children = []; this.dataset = {}; }
    append(...v) { this.children.push(...v); }
    replaceChildren() { this.children = []; }
}
const flatten = e => [e, ...e.children.flatMap(flatten)];

const file = path.resolve(__dirname, '../Kombit.Samples.CH.WebsiteDemo/EmergencyAssets/emergency.js');
const source = fs.readFileSync(file, 'utf8');
new vm.Script(source);
assert(!source.includes('emergency_credential'), 'the browser must not handle emergency credentials');
assert(!source.includes('activate-stored') && !source.includes('activate-options'));
assert(!source.includes('navigator.credentials'));
assert(!/[^.\w]confirm\(/.test(source), 'native confirm() dialogs are suppressed by some browsers');
assert(!source.includes('Browser copy missing'));
const helpersStart = source.indexOf("    const markerKey = 'saml-emergency-login-v1';");
const helpersEnd = source.indexOf('    function control(label, work, variant) {', helpersStart);
const listStart = source.indexOf('    async function displayKeys()');
const listEnd = source.indexOf("    connect('exit'", listStart);
assert(helpersStart > 0 && helpersEnd > helpersStart && listStart > 0 && listEnd > listStart);
const code = source.slice(helpersStart, helpersEnd) + source.slice(listStart, listEnd);

function storage(initial) {
    const values = new Map(Object.entries(initial || {}));
    return { getItem: k => (values.has(k) ? values.get(k) : null), setItem: (k, v) => values.set(k, String(v)), removeItem: k => values.delete(k), values };
}

async function run(scenario) {
    const container = new Element('ul');
    const credentials = [
        { binding_id: 'binding-aaaaaa', ec_id: 'old', expires_at: 1900000000, status: 'replaced' },
        { binding_id: 'binding-aaaaaa', ec_id: 'new', expires_at: 2000000000, status: 'active', renew_soon: false },
        { binding_id: 'binding-bbbbbb', ec_id: 'other', expires_at: 2000000000, status: 'active', renew_soon: false },
    ];
    let state = { can_prepare: true, credentials: scenario === 'empty' ? [] : credentials.slice() };
    const local = storage({ 'saml-emergency-login-v1': JSON.stringify([{ binding_id: 'binding-aaaaaa', expires_at: 2000000000 }]) });
    const calls = [];
    const ctx = {
        document: { getElementById: () => container },
        page: { dataset: { mode: 'prepare' } },
        localStorage: local,
        send: async (op, body) => {
            calls.push([op, body]);
            if (op === 'status') return state;
            if (op === 'remove') {
                if (scenario === 'failed-remove') throw Error('unavailable');
                state = { ...state, credentials: state.credentials.filter(c => c.binding_id !== body.binding_id) };
                return { removed: true };
            }
            return {};
        },
        element: (...a) => new Element(...a),
        confirmControl: (label, prompt, fn) => Object.assign(new Element('button', 'danger', label), { fn }),
        statusLabels: { active: 'Active', replaced: 'Replaced', pending: 'Not activated' },
        show: () => {},
        Date, Map, Set, JSON, Array,
    };
    vm.createContext(ctx);
    vm.runInContext(code + ';globalThis.run=displayKeys;', ctx);
    await ctx.run();
    return { container, calls, local };
}

(async () => {
    let r = await run('present');
    let rows = r.container.children;
    assert.equal(rows.length, 2, 'one row per key, newest credential only');
    let texts = flatten(r.container).map(n => n.textContent);
    assert.equal(texts.filter(t => t === 'This browser').length, 1, 'only the key set up here is marked');
    assert(!texts.includes('Replaced'), 'older credentials of a key are not listed');
    const buttons = flatten(r.container).filter(n => n.tag === 'button');
    assert.deepEqual(buttons.map(b => b.textContent), ['Remove key', 'Remove key']);
    console.log('manage keys: list passed');

    r = await run('remove');
    await flatten(r.container).filter(n => n.tag === 'button')[0].fn();
    assert.equal(r.calls.find(c => c[0] === 'remove')[1].binding_id, 'binding-aaaaaa');
    assert.equal(r.local.getItem('saml-emergency-login-v1'), null, 'removing the key clears this browser\'s marker');
    assert.equal(r.container.children.length, 1);
    console.log('manage keys: remove passed');

    r = await run('failed-remove');
    await assert.rejects(flatten(r.container).filter(n => n.tag === 'button')[0].fn());
    assert.notEqual(r.local.getItem('saml-emergency-login-v1'), null, 'a failed removal keeps the marker');
    console.log('manage keys: failed-remove passed');

    r = await run('empty');
    assert.equal(r.container.children.length, 1);
    assert.match(r.container.children[0].textContent, /No emergency keys/);
    console.log('manage keys: empty passed');
})().catch(e => { console.error(e); process.exitCode = 1; });
