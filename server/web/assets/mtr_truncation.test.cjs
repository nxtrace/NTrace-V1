const test = require('node:test');
const assert = require('node:assert/strict');

const {pathEndTTL, filterRows, responseForRow} = require('./mtr_path.js');

const rows = [
  {ttl: 1, ip: '192.0.2.1'},
  {ttl: 2, ip: '198.51.100.2'},
  {ttl: 3, ip: '203.0.113.3'},
  {ttl: 4, ip: '203.0.113.4'},
];

test('target-IP transit does not infer a path edge', () => {
  const records = [
    {ttl: 2, ip: '203.0.113.10', response: {kind: 'transit'}},
    {ttl: 3, ip: '203.0.113.3', response: {kind: 'transit'}},
  ];

  assert.equal(pathEndTTL(null), Infinity);
  assert.deepEqual(filterRows(records, null), records);
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
