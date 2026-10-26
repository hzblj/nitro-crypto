import {type CborLimits, type CborValue, decodeCbor, encodeCbor, isCborTagged} from './cbor'
import {AirgapError} from './errors'
import {isURType, type UR} from './ur'

/**
 * One UR type: its name, its CBOR tag, and the two directions between a typed value and its CBOR. `fromCbor` is where
 * hostile input is met: it checks every field it reads and throws `INVALID_PROTOCOL_DATA` (or `PRIVATE_KEY_MATERIAL`)
 * rather than return a value its type does not promise. A chain package defines its types with this, and nothing in
 * the UR codec changes.
 */
export type URType<Type extends string = string, Value = unknown> = {
  /** The UR type name, as in `ur:crypto-psbt/…`. */
  readonly type: Type
  /** The CBOR tag that marks a value of this type inside another (`#6.304(keypath)`), when the registry gives one. */
  readonly tag: number | undefined
  readonly toCbor: (value: Value) => CborValue
  readonly fromCbor: (item: CborValue) => Value
}

/** Any UR type, whatever its value: what a registry holds. */
export type AnyURType = {
  readonly type: string
  readonly tag: number | undefined
  readonly toCbor: (value: never) => CborValue
  readonly fromCbor: (item: CborValue) => unknown
}

/** The value a UR type decodes to. */
export type ValueOf<T extends AnyURType> = ReturnType<T['fromCbor']>

/** Declares a UR type. Returns it frozen and unchanged; the point is the inference of its name and value type. */
export const defineURType = <const Type extends string, Value>(
  definition: URType<Type, Value>
): URType<Type, Value> => {
  if (!isURType(definition.type)) {
    throw new AirgapError('INVALID_ARGUMENT', 'A UR type name is lowercase letters, digits and dashes.')
  }

  return Object.freeze({...definition})
}

/** The UR of `value`: its type's name and the deterministic CBOR of the value, untagged as a UR's top level is. */
export const toUR = <Type extends string, Value>(urType: URType<Type, Value>, value: Value): UR<Type> =>
  Object.freeze({cbor: encodeCbor(urType.toCbor(value)), type: urType.type})

/** The top level of a UR is untagged; an encoder that tags it anyway with the type's own tag is read all the same. */
const unwrapTopLevel = (item: CborValue, tag: number | undefined) =>
  isCborTagged(item) && tag !== undefined && item.tag === tag ? item.value : item

/**
 * The value a UR carries, checked against its type. Throws `UNSUPPORTED_UR_TYPE` for a UR of another type,
 * `INVALID_CBOR` for bytes that are not CBOR, and whatever the type's `fromCbor` throws for CBOR that breaks it.
 */
export const fromUR = <Type extends string, Value>(urType: URType<Type, Value>, ur: UR, limits?: CborLimits): Value => {
  if (ur.type !== urType.type) {
    throw new AirgapError('UNSUPPORTED_UR_TYPE', `Expected a ${urType.type} UR, not a ${ur.type} one.`)
  }

  return urType.fromCbor(unwrapTopLevel(decodeCbor(ur.cbor, limits), urType.tag))
}

/** What a registry decodes a UR to: the type's name beside its value, a union discriminated by `type`. */
export type DecodedUR<Types extends readonly AnyURType[]> = {
  [Index in keyof Types]: {readonly type: Types[Index]['type']; readonly value: ValueOf<Types[Index]>}
}[number]

export type URRegistry<Types extends readonly AnyURType[]> = {
  /** The type names, to pass as a decoder's `allowedTypes`. */
  readonly types: readonly Types[number]['type'][]
  /** The value of a UR of any of the registry's types. Throws `UNSUPPORTED_UR_TYPE` for any other. */
  readonly decode: (ur: UR, limits?: CborLimits) => DecodedUR<Types>
}

/**
 * The UR types a screen accepts, together: one scanner for several kinds of request, and a value whose `type` says
 * which arrived. Nothing is registered globally; each registry is the list it is given.
 */
export const createURRegistry = <const Types extends readonly AnyURType[]>(types: Types): URRegistry<Types> => {
  const byName = new Map<string, AnyURType>()

  for (const urType of types) {
    if (byName.has(urType.type)) {
      throw new AirgapError('INVALID_ARGUMENT', `${urType.type} is in the registry twice.`)
    }

    byName.set(urType.type, urType)
  }

  return Object.freeze({
    decode: (ur: UR, limits?: CborLimits) => {
      const urType = byName.get(ur.type)

      if (!urType) {
        throw new AirgapError('UNSUPPORTED_UR_TYPE', `A ${ur.type} UR is not one this accepts.`)
      }

      return Object.freeze({
        type: ur.type,
        value: urType.fromCbor(unwrapTopLevel(decodeCbor(ur.cbor, limits), urType.tag)),
      }) as DecodedUR<Types>
    },
    types: Object.freeze([...byName.keys()]) as readonly Types[number]['type'][],
  })
}
