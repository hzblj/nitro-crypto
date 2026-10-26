import {useCallback, useEffect, useState} from 'react'

import {useCrypto} from '../crypto'
import {runChecks, type VectorResult} from './checks'

export type ChecksState = {
  readonly results: readonly VectorResult[] | null
  readonly running: boolean
  readonly run: () => void
}

/** The vector checks, run once when the screen mounts and again on `run()`. */
export const useChecks = (): ChecksState => {
  const {crypto} = useCrypto()
  const [results, setResults] = useState<readonly VectorResult[] | null>(null)
  const [running, setRunning] = useState(false)

  const run = useCallback(() => {
    if (!crypto) {
      return
    }
    setRunning(true)
    runChecks(crypto)
      .then(setResults)
      .finally(() => setRunning(false))
  }, [crypto])

  useEffect(run, [run])

  return {results, run, running}
}
