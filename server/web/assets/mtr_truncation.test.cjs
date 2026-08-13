const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const mtrPath = require('./mtr_path.js');
const {pathEndTTL, filterRows, responseForRow} = mtrPath;

function loadAppRawIngestor() {
  const classList = {add() {}, remove() {}, toggle() {}};
  const element = () => ({
    classList,
    dataset: {},
    parentElement: {classList},
    addEventListener() {},
  });
  const context = vm.createContext({
    console,
    document: {
      body: {classList},
      getElementById: element,
      addEventListener() {},
    },
    window: {
      location: {protocol: 'http:', host: 'example.test'},
      nextTraceMTRPath: mtrPath,
    },
  });
  const appPath = path.join(__dirname, 'app.js');
  vm.runInContext(fs.readFileSync(appPath, 'utf8'), context, {filename: appPath});

  return (records, summary) => {
    context.__records = records;
    context.__summary = summary;
    vm.runInContext(`
      mtrRawAggStore = new Map();
      mtrRawOrderSeq = 0;
      latestSummary = __summary;
      __records.forEach(ingestMTRRawRecord);
      globalThis.__rows = buildMTRStatsFromRawAgg();
    `, context);
    return JSON.parse(JSON.stringify(context.__rows));
  };
}

const rows = [
  {ttl: 1, ip: '192.0.2.1'},
  {ttl: 2, ip: '198.51.100.2'},
  {ttl: 3, ip: '203.0.113.3'},
  {ttl: 4, ip: '203.0.113.4'},
];

test('target-IP transit does not infer a path edge', () => {
  const ingest = loadAppRawIngestor();
  const records = [
    {ttl: 2, ip: '203.0.113.10', response: {kind: 'transit'}},
    {ttl: 3, ip: '203.0.113.3', response: {kind: 'transit'}},
  ];

  assert.equal(pathEndTTL(null), Infinity);
  assert.deepEqual(ingest(records, {resolved_ip: '203.0.113.10', path_end: null}).map(({ttl, ip}) => ({ttl, ip})), [
    {ttl: 2, ip: '203.0.113.10'},
    {ttl: 3, ip: '203.0.113.3'},
  ]);
});

test('different-source destination path_end truncates by semantic hop', () => {
  const pathEnd = {hop: 2, reason: 'destination_reached'};
  assert.equal(pathEndTTL(pathEnd), 2);
  assert.deepEqual(filterRows(rows, pathEnd), rows.slice(0, 2));
});

test('unreachable path_end is provisional and null reopens preserved rows', () => {
  const pathEnd = {hop: 2, reason: 'unreachable', markers: ['!H']};
  assert.deepEqual(filterRows(rows, pathEnd), rows.slice(0, 2));
  assert.deepEqual(filterRows(rows, null), rows);
});

test('lower path_end filters stale higher rows without mutating storage', () => {
  const stored = rows.map((row) => ({...row}));
  assert.deepEqual(filterRows(stored, {hop: 4, reason: 'destination_reached'}), stored);
  assert.deepEqual(filterRows(stored, {hop: 2, reason: 'destination_reached'}), stored.slice(0, 2));
  assert.equal(stored.length, 4);
});

test('invalid or missing path_end leaves rows visible', () => {
  assert.equal(pathEndTTL({hop: 0, reason: 'unreachable'}), Infinity);
  assert.equal(pathEndTTL({hop: 'invalid'}), Infinity);
  assert.deepEqual(filterRows(rows, {hop: 0}), rows);
  assert.deepEqual(filterRows(undefined, null), []);
});

test('unreachable marker follows the current path edge, not a stale raw response', () => {
  const row = {ttl: 2, response: {kind: 'unreachable', marker: '!H'}};

  assert.equal(responseForRow(row, null), undefined);
  assert.equal(responseForRow(row, {hop: 3, reason: 'unreachable', markers: ['!N']}), undefined);
  assert.deepEqual(responseForRow(row, {hop: 2, reason: 'unreachable', markers: ['!H']}), {
    kind: 'unreachable',
    marker: '!H',
  });
  assert.equal(responseForRow(row, {hop: 2, reason: 'destination_reached'}), undefined);
});
