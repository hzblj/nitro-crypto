import {utf8} from '../encoding/utf8'
import type {
  Curve,
  DerivationScheme,
  HashAlgorithm,
  HmacAlgorithm,
  NitroCrypto,
  NitroKey,
  NitroSeed,
} from '../specs/nitro-crypto.nitro'
import {ENGINE_WASM_BASE64} from './wasm-binary.generated'

/**
 * The engine compiled to WebAssembly, behind the same `NitroCrypto` interface the native module implements: what
 * `@hzblj/nitro-crypto/testing` runs. Every method is the C ABI call `cpp/` makes, with the same arguments, so a
 * test through this host exercises the code a phone runs, minus the bridge.
 */

type Pointer = number
type Handle = bigint
type Status = number

/** The engine's exports. `usize` is a number on wasm32; `nc_handle` (u64) is a bigint. */
type Exports = {
  readonly memory: WebAssembly.Memory
  readonly _initialize: () => void
  readonly nc_wasm_alloc: (length: number) => Pointer
  readonly nc_wasm_free: (pointer: Pointer, length: number) => void
  readonly nc_status_name: (status: Status) => Pointer
  readonly nc_abi_version: () => number
  readonly nc_engine_version: () => Pointer
  readonly nc_build_info: () => Pointer
  readonly nc_capabilities: () => bigint
  readonly nc_capability_name: (bit: number) => Pointer
  readonly nc_handle_count: () => number
  readonly nc_handle_destroy: (handle: Handle) => Status
  readonly nc_random_bytes: (out: Pointer, length: number) => Status
  readonly nc_hash_length: (algorithm: number) => number
  readonly nc_hash: (algorithm: number, data: Pointer, length: number, out: Pointer, outLength: number) => Status
  readonly nc_hmac: (...args: [number, Pointer, number, Pointer, number, Pointer, number]) => Status
  readonly nc_secp256k1_public_key_convert: (...args: [Pointer, number, number, Pointer, number, Pointer]) => Status
  readonly nc_secp256k1_verify: (...args: [Pointer, number, Pointer, number, Pointer, number]) => Status
  readonly nc_secp256k1_recover: (
    ...args: [Pointer, number, Pointer, number, number, Pointer, number, Pointer]
  ) => Status
  readonly nc_ed25519_verify: (...args: [Pointer, number, Pointer, number, Pointer, number]) => Status
  readonly nc_mnemonic_validate: (mnemonic: Pointer, length: number) => Status
  readonly nc_seed_generate: (words: number, passphrase: Pointer, length: number, out: Pointer) => Status
  readonly nc_seed_from_mnemonic: (...args: [Pointer, number, Pointer, number, Pointer]) => Status
  readonly nc_seed_fingerprint: (seed: Handle, out: Pointer) => Status
  readonly nc_handle_kind: (handle: Handle, out: Pointer) => Status
  readonly nc_key_derive: (seed: Handle, scheme: number, path: Pointer, length: number, out: Pointer) => Status
  readonly nc_key_generate: (curve: number, out: Pointer) => Status
  readonly nc_key_import: (curve: number, secret: Pointer, length: number, out: Pointer) => Status
  readonly nc_key_public: (key: Handle, compressed: number, out: Pointer, length: number, written: Pointer) => Status
  readonly nc_key_sign: (...args: [Handle, Pointer, number, Pointer, number, Pointer]) => Status
}

// The header's constants (include/nitro_crypto.h).
const OK = 0
const VERIFICATION_FAILED = -7
const HASHES: Record<HashAlgorithm, number> = {keccak256: 3, ripemd160: 4, sha256: 1, sha512: 2}
const CURVES: Record<Curve, number> = {ed25519: 2, secp256k1: 1}
const SCHEMES: Record<DerivationScheme, number> = {bip32: 1, slip10: 2}
const KEY_KINDS: Record<number, Curve> = {2: 'secp256k1', 3: 'ed25519'}
/** The largest output any call writes: an uncompressed public key, a recoverable signature, a SHA-512 digest. */
const MAX_OUTPUT = 65
/** WASI's EIO: `random_get` returns it when the host has no CSPRNG, and the engine then fails closed. */
const EIO = 29
/** `crypto.getRandomValues` fills at most this many bytes per call. */
const RANDOM_CHUNK = 65536

const decodeBase64 = (text: string): Uint8Array<ArrayBuffer> => Uint8Array.from(atob(text), char => char.charCodeAt(0))

const toBytes = (data: ArrayBuffer): Uint8Array => new Uint8Array(data)

/** Owns the buffers of one call in linear memory, and zeroes and frees every one of them afterwards. */
class Frame {
  private readonly allocations: [Pointer, number][] = []

  constructor(private readonly engine: Exports) {}

  input(data: ArrayBuffer | Uint8Array): [Pointer, number] {
    const bytes = data instanceof Uint8Array ? data : toBytes(data)
    const pointer = this.allocate(bytes.length)
    new Uint8Array(this.engine.memory.buffer, pointer, bytes.length).set(bytes)

    return [pointer, bytes.length]
  }

  allocate(length: number): Pointer {
    const pointer = this.engine.nc_wasm_alloc(length)

    if (pointer === 0) {
      throw new Error('NC_ERR_INTERNAL')
    }

    this.allocations.push([pointer, length])

    return pointer
  }

  /** A copy out of linear memory: the view would not survive the next allocation growing it. */
  read(pointer: Pointer, length: number): ArrayBuffer {
    return new Uint8Array(this.engine.memory.buffer, pointer, length).slice().buffer
  }

  view(): DataView {
    return new DataView(this.engine.memory.buffer)
  }

  release(): void {
    for (const [pointer, length] of this.allocations) {
      this.engine.nc_wasm_free(pointer, length)
    }
  }
}

const readCString = (engine: Exports, pointer: Pointer): string => {
  const memory = new Uint8Array(engine.memory.buffer)
  let end = pointer

  while (memory[end] !== 0) {
    end++
  }

  return String.fromCharCode(...memory.subarray(pointer, end))
}

const createRuntime = () => {
  let engine: Exports | undefined
  const imports = {
    wasi_snapshot_preview1: {
      random_get: (pointer: Pointer, length: number): number => {
        if (!engine || typeof globalThis.crypto?.getRandomValues !== 'function') {
          return EIO
        }

        for (let offset = 0; offset < length; offset += RANDOM_CHUNK) {
          const size = Math.min(RANDOM_CHUNK, length - offset)
          globalThis.crypto.getRandomValues(new Uint8Array(engine.memory.buffer, pointer + offset, size))
        }

        return 0
      },
    },
  }
  const instance = new WebAssembly.Instance(new WebAssembly.Module(decodeBase64(ENGINE_WASM_BASE64)), imports)
  engine = instance.exports as unknown as Exports
  engine._initialize()

  return engine
}

export const createWasmHost = (): NitroCrypto => {
  const engine = createRuntime()

  /** Runs one C ABI call in a frame, and throws the status's name as the native bridge does. */
  const call = <T>(body: (frame: Frame, check: (status: Status) => void) => T): T => {
    const frame = new Frame(engine)
    const check = (status: Status) => {
      if (status !== OK) {
        throw new Error(readCString(engine, engine.nc_status_name(status)))
      }
    }

    try {
      return body(frame, check)
    } finally {
      frame.release()
    }
  }

  const verified = (status: Status, check: (status: Status) => void) => {
    if (status === VERIFICATION_FAILED) {
      return false
    }

    check(status)

    return true
  }

  /** An output buffer of `MAX_OUTPUT` bytes and the length the engine wrote into it. */
  const withOutput = (write: (frame: Frame, out: Pointer, written: Pointer) => Status) =>
    call((frame, check) => {
      const out = frame.allocate(MAX_OUTPUT)
      const written = frame.allocate(4)
      check(write(frame, out, written))

      return frame.read(out, frame.view().getUint32(written, true))
    })

  const handleOut = (create: (frame: Frame, out: Pointer) => Status): Handle =>
    call((frame, check) => {
      const out = frame.allocate(8)
      check(create(frame, out))

      return frame.view().getBigUint64(out, true)
    })

  /** Mirrors the C++ destructor: a handle the garbage collector reaches is destroyed, if `dispose()` did not. */
  const finalizer = new FinalizationRegistry<{handle: Handle}>(owner => {
    if (owner.handle !== 0n) {
      engine.nc_handle_destroy(owner.handle)
    }
  })

  const hybrid = <T extends object>(name: string, members: T, owner: {handle: Handle}) => {
    const object = {
      ...members,
      dispose: () => {
        if (owner.handle !== 0n) {
          engine.nc_handle_destroy(owner.handle)
          owner.handle = 0n
        }
      },
      equals: (other: unknown) => other === object,
      name,
      toString: () => `[HybridObject ${name}]`,
    }
    finalizer.register(object, owner)

    return object
  }

  /** The live handle, or what the native bridge throws for a disposed one. */
  const live = (owner: {handle: Handle}) => {
    if (owner.handle === 0n) {
      throw new Error('NC_ERR_INVALID_HANDLE')
    }

    return owner.handle
  }

  const createKey = (handle: Handle): NitroKey => {
    const owner = {handle}
    const kind = call((frame, check) => {
      const out = frame.allocate(4)
      check(engine.nc_handle_kind(handle, out))

      return frame.view().getUint32(out, true)
    })
    const curve = KEY_KINDS[kind]

    if (!curve) {
      throw new Error('NC_ERR_INVALID_HANDLE')
    }

    return hybrid(
      'NitroKey',
      {
        curve,
        getPublicKey: (compressed: boolean) =>
          withOutput((_, out, written) =>
            engine.nc_key_public(live(owner), compressed ? 1 : 0, out, MAX_OUTPUT, written)
          ),
        sign: (data: ArrayBuffer) =>
          withOutput((frame, out, written) => {
            const [pointer, length] = frame.input(data)

            return engine.nc_key_sign(live(owner), pointer, length, out, MAX_OUTPUT, written)
          }),
      },
      owner
    )
  }

  const createSeed = (handle: Handle): NitroSeed => {
    const owner = {handle}
    const fingerprint = call((frame, check) => {
      const out = frame.allocate(4)
      check(engine.nc_seed_fingerprint(handle, out))

      return frame.view().getUint32(out, true)
    })

    return hybrid(
      'NitroSeed',
      {
        deriveKey: (scheme: DerivationScheme, path: string) =>
          createKey(
            handleOut((frame, out) => {
              const [pointer, length] = frame.input(utf8.encode(path))

              return engine.nc_key_derive(live(owner), SCHEMES[scheme], pointer, length, out)
            })
          ),
        fingerprint,
      },
      owner
    )
  }

  /** The bridge's async methods run on a thread pool; here they run now and settle as a promise. */
  const settle = <T>(run: () => T): Promise<T> => {
    try {
      return Promise.resolve(run())
    } catch (error) {
      return Promise.reject(error)
    }
  }

  const hash = (algorithm: HashAlgorithm, data: ArrayBuffer) =>
    call((frame, check) => {
      const [pointer, length] = frame.input(data)
      const size = engine.nc_hash_length(HASHES[algorithm])
      const out = frame.allocate(size)
      check(engine.nc_hash(HASHES[algorithm], pointer, length, out, size))

      return frame.read(out, size)
    })

  const capabilities = (() => {
    const mask = engine.nc_capabilities()
    const names: string[] = []

    for (let bit = 0; bit < 64; bit++) {
      const name = engine.nc_capability_name(bit)

      if (name !== 0 && (mask >> BigInt(bit)) & 1n) {
        names.push(readCString(engine, name))
      }
    }

    return names
  })()

  const host: NitroCrypto = {
    abiVersion: engine.nc_abi_version(),
    buildInfo: readCString(engine, engine.nc_build_info()),
    capabilities,
    dispose: () => undefined,
    ed25519Verify: (publicKey, message, signature) =>
      call((frame, check) => {
        const [key, keyLength] = frame.input(publicKey)
        const [data, dataLength] = frame.input(message)
        const [sig, sigLength] = frame.input(signature)

        return verified(engine.nc_ed25519_verify(key, keyLength, data, dataLength, sig, sigLength), check)
      }),
    engineVersion: readCString(engine, engine.nc_engine_version()),
    equals: other => other === host,
    generateKey: curve => createKey(handleOut((_, out) => engine.nc_key_generate(CURVES[curve], out))),
    generateSeed: (wordCount, passphrase) =>
      settle(() =>
        createSeed(
          handleOut((frame, out) => {
            const [pointer, length] = frame.input(passphrase)

            return engine.nc_seed_generate(wordCount, pointer, length, out)
          })
        )
      ),
    hash,
    hashAsync: (algorithm, data) => settle(() => hash(algorithm, data)),
    hmac: (algorithm: HmacAlgorithm, key, data) =>
      call((frame, check) => {
        const [keyPointer, keyLength] = frame.input(key)
        const [dataPointer, dataLength] = frame.input(data)
        const size = engine.nc_hash_length(HASHES[algorithm])
        const out = frame.allocate(size)
        check(engine.nc_hmac(HASHES[algorithm], keyPointer, keyLength, dataPointer, dataLength, out, size))

        return frame.read(out, size)
      }),
    importKey: (curve, secret) =>
      createKey(
        handleOut((frame, out) => {
          const [pointer, length] = frame.input(secret)

          return engine.nc_key_import(CURVES[curve], pointer, length, out)
        })
      ),
    get liveHandles() {
      return engine.nc_handle_count()
    },
    name: 'NitroCrypto',
    randomBytes: length =>
      call((frame, check) => {
        const out = frame.allocate(length)
        check(engine.nc_random_bytes(out, length))

        return frame.read(out, length)
      }),
    secp256k1ConvertPublicKey: (publicKey, compressed) =>
      withOutput((frame, out, written) => {
        const [pointer, length] = frame.input(publicKey)

        return engine.nc_secp256k1_public_key_convert(pointer, length, compressed ? 1 : 0, out, MAX_OUTPUT, written)
      }),
    secp256k1Recover: (digest, signature, compressed) =>
      withOutput((frame, out, written) => {
        const [message, messageLength] = frame.input(digest)
        const [sig, sigLength] = frame.input(signature)

        return engine.nc_secp256k1_recover(
          message,
          messageLength,
          sig,
          sigLength,
          compressed ? 1 : 0,
          out,
          MAX_OUTPUT,
          written
        )
      }),
    secp256k1Verify: (publicKey, digest, signature) =>
      call((frame, check) => {
        const [key, keyLength] = frame.input(publicKey)
        const [message, messageLength] = frame.input(digest)
        const [sig, sigLength] = frame.input(signature)

        return verified(engine.nc_secp256k1_verify(key, keyLength, message, messageLength, sig, sigLength), check)
      }),
    seedFromMnemonic: (mnemonic, passphrase) =>
      settle(() =>
        createSeed(
          handleOut((frame, out) => {
            const [words, wordsLength] = frame.input(mnemonic)
            const [secret, secretLength] = frame.input(passphrase)

            return engine.nc_seed_from_mnemonic(words, wordsLength, secret, secretLength, out)
          })
        )
      ),
    toString: () => '[HybridObject NitroCrypto]',
    validateMnemonic: mnemonic =>
      call((frame, check) => {
        const [pointer, length] = frame.input(mnemonic)
        check(engine.nc_mnemonic_validate(pointer, length))
      }),
  }

  return host
}
