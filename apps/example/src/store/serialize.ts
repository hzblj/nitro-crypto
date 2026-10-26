type TaggedValue =
  | {__type: 'BigInt'; value: string}
  | {__type: 'Date'; value: string}
  | {__type: 'Map'; value: Record<string, unknown>}
  | {__type: 'Set'; value: unknown[]}

const isTaggedValue = (value: unknown): value is TaggedValue =>
  typeof value === 'object' && value !== null && '__type' in value

/**
 * A function declaration on purpose: `JSON.stringify` calls `Date.prototype.toJSON` before a replacer sees the value,
 * so only `this[key]` still holds the `Date`. `bigint` has no JSON form at all; balances and amounts are bigints.
 */
export function replacer(this: Record<string, unknown>, key: string, value: unknown): unknown {
  const original = this[key]

  if (original instanceof Date) {
    return {__type: 'Date', value: original.toISOString()} satisfies TaggedValue
  }

  if (typeof value === 'bigint') {
    return {__type: 'BigInt', value: value.toString()} satisfies TaggedValue
  }

  if (value instanceof Map) {
    return {__type: 'Map', value: Object.fromEntries(value)} satisfies TaggedValue
  }

  if (value instanceof Set) {
    return {__type: 'Set', value: Array.from(value)} satisfies TaggedValue
  }

  return value
}

export const reviver = (_: string, value: unknown): unknown => {
  if (!isTaggedValue(value)) {
    return value
  }

  switch (value.__type) {
    case 'BigInt':
      return BigInt(value.value)
    case 'Date':
      return new Date(value.value)
    case 'Map':
      return new Map(Object.entries(value.value))
    case 'Set':
      return new Set(value.value)
  }
}

/** JSON that keeps `bigint`, `Date`, `Map` and `Set`: what the stores write, and only `parse` reads it back. */
export const stringify = (value: unknown, space?: number) => JSON.stringify(value, replacer, space)

export const parse = (text: string): unknown => JSON.parse(text, reviver)
