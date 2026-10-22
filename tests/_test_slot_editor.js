/* The proxy-slot editor must survive the panel's polling (issue #79).
 *
 * loadAccounts() runs every 15 seconds and used to refresh the slot list with
 * it. That refresh replaces the whole list and re-renders the table, so a row
 * the operator had just added with 「+ 添加槽位」 - not saved to the server yet -
 * was wiped before they could type anything into it. The editor now refuses to
 * be refreshed while it holds unsaved changes, and says so in its header.
 *
 * Run with Node: node tests/_test_slot_editor.js
 */
const assert = require('assert');
const {dashboardScript} = require('./_dashboard_source.js');

const script = dashboardScript();

// One shared fake DOM for every dashboard suite: tests/_dom_stub.js.
const dom = require('./_dom_stub.js');

// What the server would return for GET /proxy/slots; the test swaps it.
let serverSlots = [];
let saveRequests = 0;
dom.installDom({
  confirm: () => true,
  fetch: (url, options) => {
    if(options && options.method === 'POST' && url === '/proxy/slots/save'){
      saveRequests++;
      const incoming = JSON.parse(options.body).slots;
      serverSlots = incoming.map((slot, index) => Object.assign({}, slot, {
        id: slot.id || ('slot-new-' + index),
        bound: slot.bound || 0,
      }));
    }
    const payload = {current: 'intl', accounts: [], slots: serverSlots, data: [],
                     results: [], byAccount: []};
    return Promise.resolve({status: 200, ok: true,
      json: () => Promise.resolve(payload),
      text: () => Promise.resolve(JSON.stringify(payload))});
  },
});

const api = new Function(script + `
  window.updateUI = updateUI;
  window.toast = toast;
  return {
    loadProxySlots,
    addProxySlotRow,
    saveProxySlots,
    parseRegistrationProxyBatch,
    updateRegistrationProxyBatchCount,
    saveRegistrationProxyBatch,
    registrationProxyPoolText,
    mergeRegistrationProxyEntries,
    rows: () => PROXY_SLOTS,
    dirty: () => SLOTS_DIRTY,
    registrationDirty: () => REGISTRATION_PROXY_DIRTY,
    state: () => (document.getElementById('slotState') || {}).textContent,
  };`)();

(async () => {
  // 1. A clean editor follows the server.
  serverSlots = [{id: 'a', name: 'a', url: 'http://127.0.0.1:1', enabled: true}];
  await api.loadProxySlots();
  assert.equal(api.rows().length, 1, 'a clean editor loads the server list');

  // 2. Adding a row marks the editor dirty, and the header says so.
  api.addProxySlotRow();
  assert.equal(api.rows().length, 2, 'the new row is in the working copy');
  assert.equal(api.dirty(), true, 'adding a row marks the editor dirty');
  assert.ok(api.state().includes('未保存'), 'the header admits the list is unsaved: ' + api.state());

  // 3. The periodic refresh must not wipe it (this is the reported bug).
  serverSlots = [{id: 'a', name: 'a', url: 'http://127.0.0.1:1', enabled: true},
                 {id: 'b', name: 'b', url: 'http://127.0.0.1:2', enabled: true}];
  await api.loadProxySlots();
  assert.equal(api.rows().length, 2, 'the poll must not replace the working copy');
  // The new row is the one with no id yet - the server rows above all have
  // one - so a poll that replaced the working copy would fail this.
  assert.equal(api.rows()[1].id, '',
               'the row being filled in is still there: ' + JSON.stringify(api.rows()[1]));

  // 4. An explicit refresh still can - the polling path is the only one held.
  await api.loadProxySlots(true);
  assert.equal(api.rows().map(r => r.id).join(','), 'a,b',
               'force reloads from the server: ' + JSON.stringify(api.rows()));

  // 5. Saving clears the flag, so polling resumes afterwards.
  api.addProxySlotRow();
  assert.equal(api.dirty(), true, 'the new row is unsaved again');
  await api.saveProxySlots(null).catch(() => {});
  assert.equal(api.dirty(), false, 'a successful save clears the dirty flag');
  assert.ok(!api.state().includes('未保存'),
            'the header stops saying unsaved: ' + api.state());

  // 6. Registration bulk input accepts the common provider formats and
  // reports bad lines without duplicating an entry inside the same paste.
  const parsed = api.parseRegistrationProxyBatch([
    'http://127.0.0.1:7001',
    'socks5://user:pass@127.0.0.1:7002',
    '127.0.0.1:7003',
    '127.0.0.1:7004:user:pass',
    '香港住宅 | http://user:pass@127.0.0.1:7005',
    '127.0.0.1:7003',
    'not a proxy',
  ].join('\n'));
  assert.equal(parsed.entries.length, 5, JSON.stringify(parsed));
  assert.equal(parsed.entries[2].url, 'http://127.0.0.1:7003');
  assert.equal(parsed.entries[3].url, 'http://user:pass@127.0.0.1:7004');
  assert.equal(parsed.entries[4].name, '香港住宅');
  assert.deepEqual(parsed.invalid, [7]);

  // 7. The registration page is a whole-pool text editor. Loading fills it
  // from saved slots instead of leaving a separate, expanded table below it.
  serverSlots = [
    {id: 'keep-a', name: 'Hong Kong A', url: 'http://127.0.0.1:7101', enabled: false,
     ip: '203.0.113.1', country: 'Hong Kong', bound: 1},
    {id: 'drop-b', name: '', url: 'http://127.0.0.1:7102', enabled: true, bound: 0},
  ];
  await api.loadProxySlots(true);
  const batch = document.getElementById('registrationProxyBatch');
  assert.equal(batch.value,
    'Hong Kong A | http://127.0.0.1:7101\nhttp://127.0.0.1:7102');
  assert.equal(api.registrationDirty(), false, 'loading saved text is not an edit');

  // 8. Saving replaces the entire pool, keeps metadata for matching URLs, and
  // leaves the normalized saved content visible in the textarea.
  batch.value = 'Renamed A | http://127.0.0.1:7101\n127.0.0.1:7103';
  api.updateRegistrationProxyBatchCount(true);
  assert.equal(api.registrationDirty(), true, 'typing marks the batch editor dirty');
  const savesBefore = saveRequests;
  assert.equal(await api.saveRegistrationProxyBatch(null), true);
  assert.equal(saveRequests, savesBefore + 1, 'one whole-pool save was sent');
  assert.equal(api.rows().length, 2, 'a missing old line is removed from the pool');
  assert.equal(api.rows()[0].id, 'keep-a', 'matching URL keeps its slot id');
  assert.equal(api.rows()[0].enabled, false, 'matching URL keeps its enabled state');
  assert.equal(api.rows()[0].ip, '203.0.113.1', 'matching URL keeps probe metadata');
  assert.ok(batch.value.includes('Renamed A | http://127.0.0.1:7101'));
  assert.ok(batch.value.includes('http://127.0.0.1:7103'));
  assert.equal(api.registrationDirty(), false, 'successful save clears the batch dirty flag');
  assert.ok(document.getElementById('registrationProxyBatchState').textContent.includes('已保存 2 个代理'));

  // 9. Invalid lines are reported and block the save without clearing text.
  batch.value = '127.0.0.1:7201\nnot a proxy';
  api.updateRegistrationProxyBatchCount(true);
  const invalidText = batch.value;
  const invalidSavesBefore = saveRequests;
  assert.equal(await api.saveRegistrationProxyBatch(null), false);
  assert.equal(saveRequests, invalidSavesBefore, 'invalid input never reaches the server');
  assert.equal(batch.value, invalidText, 'failed validation leaves the editor intact');
  assert.ok(document.getElementById('registrationProxyBatchState').textContent.includes('无效行 2'));

  console.log('slot editor assertions passed');
})().catch(error => { console.error(error); process.exit(1); });

