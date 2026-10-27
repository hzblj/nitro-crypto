import {ENGINE_WASM_BASE64} from '../src/host/wasm-binary.generated'

/**
 * The engine's C ABI as the WebAssembly build exports it, in an instance of its own: for what the facade does not
 * reach. That is the functions only native callers have (seeds from entropy, ADR 0008; backups, ADR 0009 and 0010) and
 * the test hook the native libraries lack (Schnorr signing with the auxiliary randomness given, for the published
 * vectors).
 */

type Pointer = number

/** A C ABI function: pointers, lengths and handles in (a handle, u64, is a bigint), a status out. */
type AbiFunction = (...args: (number | bigint)[]) => number

/** The functions these tests call; every other `nc_*` is exported too. */
const FUNCTIONS = [
  'nc_backup_kdf',
  'nc_backup_open',
  'nc_backup_open_with_key',
  'nc_backup_seal_with_key',
  'nc_handle_count',
  'nc_handle_destroy',
  'nc_key_import',
  'nc_seed_fingerprint',
  'nc_seed_from_entropy',
  'nc_wasm_test_sign_schnorr',
] as const

type Exports = {
  readonly memory: WebAssembly.Memory
  readonly _initialize: () => void
  readonly nc_wasm_alloc: (length: number) => Pointer
  readonly nc_wasm_free: (pointer: Pointer, length: number) => void
  readonly nc_status_name: (status: number) => Pointer
} & {readonly [Name in (typeof FUNCTIONS)[number]]: AbiFunction}

export type Frame = {
  /** Bytes copied into linear memory: their pointer and length. */
  readonly input: (bytes: Uint8Array) => [Pointer, number]
  readonly allocate: (length: number) => Pointer
  readonly read: (pointer: Pointer, length: number) => Uint8Array
  readonly u32: (pointer: Pointer) => number
  readonly u64: (pointer: Pointer) => bigint
}

export const createAbi = () => {
  let memory: WebAssembly.Memory | undefined
  const imports = {
    wasi_snapshot_preview1: {
      random_get: (pointer: Pointer, length: number) => {
        globalThis.crypto.getRandomValues(new Uint8Array((memory as WebAssembly.Memory).buffer, pointer, length))

        return 0
      },
    },
  }
  const module = new WebAssembly.Module(Uint8Array.from(atob(ENGINE_WASM_BASE64), char => char.charCodeAt(0)))
  const engine = new WebAssembly.Instance(module, imports).exports as unknown as Exports
  memory = engine.memory
  engine._initialize()

  const missing = FUNCTIONS.filter(name => typeof engine[name] !== 'function')

  if (missing.length > 0) {
    throw new Error(`The WebAssembly engine lacks ${missing.join(', ')}: rebuild it (yarn engine:wasm).`)
  }

  const statusName = (status: number) => {
    const bytes = new Uint8Array(engine.memory.buffer)
    let end = engine.nc_status_name(status)
    const start = end

    while (bytes[end] !== 0) {
      end++
    }

    return String.fromCharCode(...bytes.subarray(start, end))
  }

  /** Runs `body` with a frame whose allocations are zeroed and freed afterwards. */
  const frame = <T>(body: (frame: Frame) => T): T => {
    const allocations: [Pointer, number][] = []
    const allocate = (length: number) => {
      const pointer = engine.nc_wasm_alloc(length)
      allocations.push([pointer, length])

      return pointer
    }

    try {
      return body({
        allocate,
        input: bytes => {
          const pointer = allocate(bytes.length)
          new Uint8Array(engine.memory.buffer, pointer, bytes.length).set(bytes)

          return [pointer, bytes.length]
        },
        read: (pointer, length) => new Uint8Array(engine.memory.buffer, pointer, length).slice(),
        u32: pointer => new DataView(engine.memory.buffer).getUint32(pointer, true),
        u64: pointer => new DataView(engine.memory.buffer).getBigUint64(pointer, true),
      })
    } finally {
      for (const [pointer, length] of allocations) {
        engine.nc_wasm_free(pointer, length)
      }
    }
  }

  return {engine, frame, statusName}
}
