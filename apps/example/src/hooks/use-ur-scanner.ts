import {createMultipartDecoder, isAirgapError, type MultipartProgress, type Sha256, type UR} from '@hzblj/crypto-airgap'
import {useCallback, useEffect, useMemo, useRef, useState} from 'react'

const EMPTY: MultipartProgress = {
  expectedFragmentCount: 0,
  fraction: 0,
  receivedPartCount: 0,
  recoveredFragmentCount: 0,
  type: undefined,
}

/** What went wrong with a scan, for people: the decoder's own words, minus the jargon a code has. */
const describe = (error: unknown) => {
  if (isAirgapError(error, 'SESSION_MISMATCH')) {
    return 'That code belongs to another request than the one being read. Show one code at a time.'
  }

  if (isAirgapError(error, 'UNSUPPORTED_UR_TYPE') || isAirgapError(error, 'INVALID_UR')) {
    return 'That is not a code this screen reads.'
  }

  return error instanceof Error ? error.message : String(error)
}

/**
 * The scanned strings of one UR, whole or in parts, put back together: the camera hands each code it reads to
 * `receive`, in any order and as often as it likes, and `onComplete` gets the UR once it is whole. A code of another
 * type, or of another request, is said in `error` and the parts so far are kept. `sha256` is the engine's: without an
 * engine there is nothing to read with.
 */
export const useUrScanner = (
  allowedTypes: readonly string[],
  sha256: Sha256 | undefined,
  onComplete: (ur: UR) => void
) => {
  const decoder = useMemo(
    () => (sha256 ? createMultipartDecoder({allowedTypes, sha256}) : undefined),
    [allowedTypes, sha256]
  )
  const [progress, setProgress] = useState(EMPTY)
  const [error, setError] = useState<string | null>(null)
  const done = useRef(false)
  const complete = useRef(onComplete)
  complete.current = onComplete
  // The camera reads the same frame many times a second: only a new string is worth decoding.
  const last = useRef('')

  const reset = useCallback(() => {
    decoder?.reset()
    done.current = false
    last.current = ''
    setProgress(EMPTY)
    setError(null)
  }, [decoder])

  // A decoder holds what it read; nothing of it should outlive the screen.
  useEffect(() => () => decoder?.reset(), [decoder])

  const receive = useCallback(
    (text: string) => {
      if (!decoder) {
        setError('The native engine is not available: there is nothing to read the code with.')
        return
      }

      if (done.current || text === last.current) {
        return
      }

      last.current = text

      try {
        if (decoder.receivePart(text)) {
          setError(null)
          setProgress(decoder.progress)
        }

        if (decoder.isComplete()) {
          done.current = true
          complete.current(decoder.result())
        }
      } catch (failure) {
        setError(describe(failure))
      }
    },
    [decoder]
  )

  return {error, progress, receive, reset}
}
