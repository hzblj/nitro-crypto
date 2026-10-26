import assert from 'node:assert/strict'
import {test} from 'node:test'

import {parse, stringify} from '../src/store/serialize'

test('persisted state keeps bigint balances, dates, maps and sets through a round trip', () => {
  const state = {
    balance: 123_456_789_012_345_678_901_234_567_890n,
    holdings: [{asset: {decimals: 18, id: 'ethereum'}, balance: 1n}],
    seen: new Set(['0xabc', '0xdef']),
    sentAt: new Date('2026-10-26T12:00:00.000Z'),
    statuses: new Map([['0xabc', 'pending']]),
  }

  const restored = parse(stringify(state)) as typeof state

  assert.equal(restored.balance, state.balance)
  assert.equal(restored.holdings[0]?.balance, 1n)
  assert.ok(restored.sentAt instanceof Date)
  assert.equal(restored.sentAt.toISOString(), state.sentAt.toISOString())
  assert.deepEqual(restored.seen, state.seen)
  assert.deepEqual(restored.statuses, state.statuses)
})

test('plain JSON reads back as plain JSON', () => {
  assert.deepEqual(parse(stringify({a: [1, 'two', null], b: {c: true}})), {a: [1, 'two', null], b: {c: true}})
})
