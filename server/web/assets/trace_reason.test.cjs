const test = require('node:test');
const assert = require('node:assert/strict');

const {format} = require('./trace_reason.js');

test('formats every stable stop reason in Chinese and English', () => {
  const cases = [
    ['destination_reached', '已到达目标', 'Destination reached'],
    ['unreachable', '网络不可达', 'Network unreachable'],
    ['max_hops', '已达到最大跳数', 'Maximum hops reached'],
    ['future_reason', '未知原因', 'Unknown reason'],
  ];
  cases.forEach(([reason, cn, en]) => {
    assert.match(format({hop: 4, reason}, 'cn'), new RegExp(cn));
    assert.match(format({hop: 4, reason}, 'en'), new RegExp(en));
  });
});

test('includes response descriptions and machine markers', () => {
  assert.equal(
    format({hop: 7, reason: 'unreachable', responses: ['ICMP Host Unreachable'], markers: ['!H']}, 'en'),
    '#7 — Network unreachable — ICMP Host Unreachable — !H',
  );
});
