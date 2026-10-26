import {concatBytes, equalBytes, wipe} from './bytes'

/** Byte helpers worth sharing with applications and adapters. */
export const bytes = Object.freeze({
  concat: concatBytes,
  /** Equality without an early exit. */
  equal: equalBytes,
  /** Overwrites a buffer that held a secret. Best effort: the runtime may already have copied it. */
  wipe,
})
