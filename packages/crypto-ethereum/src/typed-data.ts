import {bytes, CryptoError, hex, utf8} from '@hzblj/nitro-crypto/adapter'

import {validateAddress} from './address'
import {chainMismatch, type EthereumNetwork} from './config'
import {MAX_UINT256, toInteger, word} from './integer'
import type {Hex, Keccak256} from './types'

/** A member of an EIP-712 struct type: its name, and its type (`uint256`, `address[]`, `Person`, `Person[2][]`). */
export type TypedDataField = {readonly name: string; readonly type: string}

/**
 * The struct types, by name, as `eth_signTypedData_v4` and viem take them. `EIP712Domain` may be among them (dApps
 * send it); when it is not, it is derived from the fields the domain has.
 */
export type TypedDataTypes = {readonly [struct: string]: readonly TypedDataField[]}

/**
 * The EIP-712 domain: who the signature is for. Each field is optional, at least one is required, and only those
 * present are signed. Integers may be text (decimal or `0x` hex), as JSON-RPC payloads carry them.
 */
export type TypedDataDomain = {
  /** The dApp or protocol, for people: "Uniswap", "Permit2". */
  readonly name?: string
  /** The signing domain's version: a signature for one version is not valid for another. */
  readonly version?: string
  /** The EIP-155 chain id. When present, it must be the adapter's: anything else is `CHAIN_MISMATCH`. */
  readonly chainId?: number | bigint | string
  /** The contract that verifies the signature. */
  readonly verifyingContract?: string
  /** A 32-byte disambiguating salt, the last resort of a protocol that has nothing else to tell its domains apart. */
  readonly salt?: Hex | Uint8Array
}

/**
 * EIP-712 typed data, in viem's shape (and `eth_signTypedData_v4`'s, once its JSON is parsed): the domain, the struct
 * types, the primary type, and the message, a value of the primary type.
 *
 * Values: `address` is a string (a mixed-case one must be EIP-55); `bool` a boolean; `string` text (hashed as UTF-8);
 * `bytes` and `bytesN` `0x` hex or a `Uint8Array` (exactly N bytes for `bytesN`); `intN` and `uintN` a `bigint`, a
 * safe integer `number`, or decimal or `0x` text, within N bits; arrays are arrays (`T[k]` exactly k items); structs
 * are objects. Members the types do not declare are ignored, as viem, ethers and MetaMask ignore them; only declared
 * members are signed, so a review screen shows what the types declare.
 */
export type TypedDataDefinition = {
  readonly domain?: TypedDataDomain
  readonly types: TypedDataTypes
  /** The struct `message` is a value of. `EIP712Domain` signs the domain alone, with `message` ignored. */
  readonly primaryType: string
  readonly message: {readonly [member: string]: unknown}
}

const DOMAIN = 'EIP712Domain'

/** The domain's fields, in the order EIP-712 lists them, each with the one type it may have. */
const DOMAIN_FIELDS: readonly TypedDataField[] = [
  {name: 'name', type: 'string'},
  {name: 'version', type: 'string'},
  {name: 'chainId', type: 'uint256'},
  {name: 'verifyingContract', type: 'address'},
  {name: 'salt', type: 'bytes32'},
]

const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/

/** What a struct may not be called: anything that reads as a Solidity elementary type, valid or not. */
const RESERVED = /^(address|bool|string|byte|bytes[0-9]*|u?int[0-9]*|u?fixed([0-9]+x[0-9]+)?|function)$/

/** `T[]` or `T[k]`, k a positive integer without leading zeros: the last dimension, and what it is of. */
const ARRAY = /^(.+)\[([1-9][0-9]*)?\]$/

const INTEGER = /^(u?)int([1-9][0-9]*)$/

const FIXED_BYTES = /^bytes([1-9][0-9]*)$/

/** How deep structs and arrays may nest: far beyond any real payload, and short of exhausting the stack. */
const MAX_DEPTH = 64

const tooDeep = () => invalid(`The typed data nests structs and arrays deeper than ${MAX_DEPTH} levels.`)

type Elementary =
  | {readonly kind: 'address' | 'bool' | 'string' | 'bytes'}
  | {readonly kind: 'fixed-bytes'; readonly size: number}
  | {readonly kind: 'integer'; readonly signed: boolean; readonly bits: number}

const elementary = (type: string): Elementary | undefined => {
  if (type === 'address' || type === 'bool' || type === 'string' || type === 'bytes') {
    return {kind: type}
  }

  const integer = INTEGER.exec(type)
  const bits = Number(integer?.[2])

  if (integer && bits % 8 === 0 && bits <= 256) {
    return {bits, kind: 'integer', signed: integer[1] === ''}
  }

  const size = Number(FIXED_BYTES.exec(type)?.[1])

  return size <= 32 ? {kind: 'fixed-bytes', size} : undefined
}

const invalid = (message: string) => new CryptoError('INVALID_ARGUMENT', message)

const hasOwn = (value: object, key: string) => Object.hasOwn(value, key)

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array)

/**
 * The struct types, checked once: names are identifiers that are not elementary types, members are unique
 * identifiers whose types are elementary types or other structs (as arrays of any dimension), no struct is unknown
 * or reachable from itself, and `EIP712Domain` (declared, or derived from the domain) has only EIP-712's fields.
 */
type Schema = {
  readonly structs: ReadonlyMap<string, readonly TypedDataField[]>
  readonly encodings: Map<string, string>
}

/** Resolves a member's type to the struct it names (through any array dimensions), or `undefined` when elementary. */
const structOf = (type: string, structs: ReadonlyMap<string, unknown>, at: string): string | undefined => {
  let base = type

  for (let match = ARRAY.exec(base); match; match = ARRAY.exec(base)) {
    base = match[1] ?? ''
  }

  if (elementary(base)) {
    return undefined
  }

  if (base === DOMAIN || !IDENTIFIER.test(base) || !structs.has(base)) {
    throw invalid(`The type of ${at} is neither an EIP-712 type nor a struct the types define.`)
  }

  return base
}

const checkFields = (struct: string, fields: unknown): readonly TypedDataField[] => {
  if (!Array.isArray(fields)) {
    throw invalid(`The struct type ${struct} is not a list of members.`)
  }

  const names = new Set<string>()

  return fields.map((field: unknown, index) => {
    if (!isRecord(field) || typeof field.name !== 'string' || typeof field.type !== 'string') {
      throw invalid(`Member ${index} of ${struct} is not a {name, type} pair of strings.`)
    }

    if (!IDENTIFIER.test(field.name)) {
      throw invalid(`The name of member ${index} of ${struct} is not an identifier.`)
    }

    if (names.has(field.name)) {
      throw invalid(`${struct} has two members named ${field.name}.`)
    }

    names.add(field.name)

    return Object.freeze({name: field.name, type: field.type})
  })
}

const presentDomainFields = (domain: Readonly<Record<string, unknown>>) =>
  DOMAIN_FIELDS.filter(field => hasOwn(domain, field.name) && domain[field.name] !== undefined)

const buildSchema = (types: unknown, domain: Readonly<Record<string, unknown>> | undefined): Schema => {
  if (!isRecord(types)) {
    throw invalid('The typed data`s types are an object of struct types.')
  }

  const structs = new Map<string, readonly TypedDataField[]>()

  for (const name of Object.keys(types)) {
    if (!IDENTIFIER.test(name) || RESERVED.test(name)) {
      throw invalid('A struct type is named with an identifier that is not an elementary type.')
    }

    structs.set(name, checkFields(name, types[name]))
  }

  const declaredDomain = structs.get(DOMAIN)

  if (declaredDomain) {
    for (const field of declaredDomain) {
      if (!DOMAIN_FIELDS.some(known => known.name === field.name && known.type === field.type)) {
        throw invalid(
          `EIP712Domain.${field.name} is not one of EIP-712's domain fields (name, version, chainId, verifyingContract, salt) with its type.`
        )
      }
    }
  } else if (domain) {
    structs.set(DOMAIN, presentDomainFields(domain))
  }

  // Every member type resolves, and no struct reaches itself: depth-first, with the structs on the current path.
  const done = new Set<string>()
  const visit = (struct: string, path: Set<string>) => {
    if (done.has(struct)) {
      return
    }

    if (path.has(struct)) {
      throw invalid(`The struct type ${struct} contains itself: EIP-712 types here are not recursive.`)
    }

    if (path.size >= MAX_DEPTH) {
      throw tooDeep()
    }

    path.add(struct)

    for (const field of structs.get(struct) ?? []) {
      const child = structOf(field.type, structs, `${struct}.${field.name}`)

      if (child) {
        visit(child, path)
      }
    }

    path.delete(struct)
    done.add(struct)
  }

  for (const struct of structs.keys()) {
    visit(struct, new Set())
  }

  return {encodings: new Map(), structs}
}

/** `Name(type member,…)`, then every struct it references, sorted by name: what EIP-712 hashes for a type. */
const encodeType = (schema: Schema, primary: string): string => {
  const cached = schema.encodings.get(primary)

  if (cached !== undefined) {
    return cached
  }

  const found = new Set<string>()
  const collect = (struct: string) => {
    for (const field of schema.structs.get(struct) ?? []) {
      const child = structOf(field.type, schema.structs, `${struct}.${field.name}`)

      if (child && child !== primary && !found.has(child)) {
        found.add(child)
        collect(child)
      }
    }
  }
  collect(primary)

  const encoded = [primary, ...[...found].sort()]
    .map(
      struct => `${struct}(${(schema.structs.get(struct) ?? []).map(({name, type}) => `${type} ${name}`).join(',')})`
    )
    .join('')
  schema.encodings.set(primary, encoded)

  return encoded
}

const HEX_BYTES = /^0x([0-9a-fA-F]{2})*$/

const bytesValue = (value: unknown, at: string): Uint8Array => {
  if (value instanceof Uint8Array) {
    return value
  }

  if (typeof value !== 'string') {
    throw invalid(`${at} is not bytes: 0x hex, or a Uint8Array.`)
  }

  if (!HEX_BYTES.test(value)) {
    throw new CryptoError('INVALID_ENCODING', `${at} is not 0x hex of whole bytes.`)
  }

  return hex.decode(value)
}

/** One elementary value, as its 32-byte word (or, for `bytes` and `string`, the Keccak-256 that stands for it). */
const encodeElementary = (kind: Elementary, value: unknown, at: string, keccak256: Keccak256): Uint8Array => {
  switch (kind.kind) {
    case 'address': {
      const address = validateAddress(typeof value === 'string' ? value : '', keccak256)

      if (!address.valid) {
        throw new CryptoError('INVALID_ADDRESS', `${at} is not a valid address. ${address.reason}`)
      }

      return word(hex.decode(address.normalized))
    }
    case 'bool':
      if (typeof value !== 'boolean') {
        throw invalid(`${at} is not a boolean.`)
      }

      return word(value ? 1n : 0n)
    case 'string':
      if (typeof value !== 'string') {
        throw invalid(`${at} is not a string.`)
      }

      return keccak256(utf8.encode(value))
    case 'bytes':
      return keccak256(bytesValue(value, at))
    case 'fixed-bytes': {
      const raw = bytesValue(value, at)

      if (raw.length !== kind.size) {
        throw invalid(`${at} is not ${kind.size} bytes.`)
      }

      const out = new Uint8Array(32)
      out.set(raw)

      return out
    }
    case 'integer': {
      const integer = toInteger(value)
      const bits = BigInt(kind.bits)
      const min = kind.signed ? -(1n << (bits - 1n)) : 0n
      const max = kind.signed ? (1n << (bits - 1n)) - 1n : (1n << bits) - 1n

      if (integer === undefined) {
        throw invalid(`${at} is not an integer: a bigint, a safe number, or decimal or 0x text.`)
      }

      if (integer < min || integer > max) {
        throw invalid(`${at} is out of range for ${kind.signed ? 'int' : 'uint'}${kind.bits}.`)
      }

      // Two's complement in 256 bits.
      return word(integer < 0n ? MAX_UINT256 + 1n + integer : integer)
    }
  }
}

const encodeValue = (
  schema: Schema,
  type: string,
  value: unknown,
  at: string,
  keccak256: Keccak256,
  depth: number
): Uint8Array => {
  if (depth > MAX_DEPTH) {
    throw tooDeep()
  }

  const array = ARRAY.exec(type)

  if (array) {
    const length = array[2] === undefined ? undefined : Number(array[2])

    if (!Array.isArray(value)) {
      throw invalid(`${at} is not an array.`)
    }

    if (length !== undefined && value.length !== length) {
      throw invalid(`${at} does not have ${length} items.`)
    }

    const item = array[1] ?? ''

    return keccak256(
      bytes.concat(
        ...value.map((entry, index) => encodeValue(schema, item, entry, `${at}[${index}]`, keccak256, depth + 1))
      )
    )
  }

  const kind = elementary(type)

  return kind ? encodeElementary(kind, value, at, keccak256) : hashData(schema, type, value, at, keccak256, depth + 1)
}

/** `hashStruct(s) = keccak256(typeHash || encodeData(s))`, every declared member present. */
const hashData = (
  schema: Schema,
  struct: string,
  value: unknown,
  at: string,
  keccak256: Keccak256,
  depth = 0
): Uint8Array => {
  if (!isRecord(value)) {
    throw invalid(`${at} is not an object of the struct type ${struct}.`)
  }

  const fields = schema.structs.get(struct) ?? []
  const words = fields.map(({name, type}) => {
    if (!hasOwn(value, name) || value[name] === undefined) {
      throw invalid(`The typed data has no value for ${at}.${name}.`)
    }

    return encodeValue(schema, type, value[name], `${at}.${name}`, keccak256, depth)
  })

  return keccak256(bytes.concat(keccak256(utf8.encode(encodeType(schema, struct))), ...words))
}

const checkDomain = (domain: unknown): Readonly<Record<string, unknown>> => {
  const resolved = domain ?? {}

  if (!isRecord(resolved)) {
    throw invalid('The typed data`s domain is an object.')
  }

  return resolved
}

/** The domain's chain id, which must be the network's when the domain has one. */
const checkDomainChain = (domain: Readonly<Record<string, unknown>>, network: EthereumNetwork | undefined) => {
  if (!hasOwn(domain, 'chainId') || domain.chainId === undefined) {
    return
  }

  const chainId = toInteger(domain.chainId)

  if (chainId === undefined || chainId < 0n || chainId > MAX_UINT256) {
    throw invalid('The domain`s chainId is not a uint256.')
  }

  if (network && chainId !== BigInt(network.chainId)) {
    throw chainMismatch(network, 'The typed data')
  }
}

const domainSeparator = (schema: Schema, domain: Readonly<Record<string, unknown>>, keccak256: Keccak256) => {
  const fields = schema.structs.get(DOMAIN) ?? []

  if (fields.length === 0) {
    throw invalid('An EIP-712 domain has at least one field: name, version, chainId, verifyingContract or salt.')
  }

  return hashData(schema, DOMAIN, domain, DOMAIN, keccak256)
}

/**
 * The EIP-712 digest a wallet signs: `keccak256(0x19 0x01 || domainSeparator || hashStruct(message))`, or without the
 * message's hash when the primary type is `EIP712Domain`. With a network, a domain chain id other than its own is
 * `CHAIN_MISMATCH`.
 */
export const hashTypedData = (
  typedData: TypedDataDefinition,
  keccak256: Keccak256,
  network?: EthereumNetwork
): Uint8Array => {
  if (!isRecord(typedData)) {
    throw invalid('Typed data is an object: domain, types, primaryType and message.')
  }

  const domain = checkDomain(typedData.domain)
  const schema = buildSchema(typedData.types, domain)
  const {primaryType} = typedData

  if (typeof primaryType !== 'string' || !schema.structs.has(primaryType)) {
    throw invalid('The primary type is not a struct the types define.')
  }

  checkDomainChain(domain, network)
  const parts = [Uint8Array.of(0x19, 0x01), domainSeparator(schema, domain, keccak256)]

  if (primaryType !== DOMAIN) {
    parts.push(hashData(schema, primaryType, typedData.message, primaryType, keccak256))
  }

  return keccak256(bytes.concat(...parts))
}

/**
 * The domain separator, `hashStruct(domain)`: what a contract's `DOMAIN_SEPARATOR()` returns. `EIP712Domain` is
 * taken from `types` when they declare it, or derived from the fields the domain has.
 */
export const hashDomain = (
  request: {readonly domain: TypedDataDomain; readonly types?: TypedDataTypes},
  keccak256: Keccak256
): Uint8Array => {
  const domain = checkDomain(isRecord(request) ? request.domain : undefined)
  checkDomainChain(domain, undefined)

  return domainSeparator(buildSchema((isRecord(request) && request.types) || {}, domain), domain, keccak256)
}

/** `hashStruct(data)` for a struct of `types`: `keccak256(typeHash || encodeData(data))`. */
export const hashStruct = (
  request: {
    readonly types: TypedDataTypes
    readonly primaryType: string
    readonly data: {readonly [member: string]: unknown}
  },
  keccak256: Keccak256
): Uint8Array => {
  if (!isRecord(request)) {
    throw invalid('A struct to hash is an object: types, primaryType and data.')
  }

  if (request.primaryType === DOMAIN) {
    return hashDomain({domain: request.data as TypedDataDomain, types: request.types}, keccak256)
  }

  const schema = buildSchema(request.types, undefined)

  if (typeof request.primaryType !== 'string' || !schema.structs.has(request.primaryType)) {
    throw invalid('The primary type is not a struct the types define.')
  }

  return hashData(schema, request.primaryType, request.data, request.primaryType, keccak256)
}
