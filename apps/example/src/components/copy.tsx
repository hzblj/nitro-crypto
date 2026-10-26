import {Box, Snackbar} from '@hzblj/kara-ui'
import {setStringAsync} from 'expo-clipboard'
import {createContext, type ReactNode, useCallback, useContext, useMemo, useState} from 'react'

type Copy = (value: string, what: string) => void

const CopyContext = createContext<Copy>(() => undefined)

/**
 * Copying, app-wide, with one snackbar that says what was copied. Only public values reach the clipboard here:
 * addresses, public keys, signatures, digests. Nothing secret has a copy button, because nothing secret is shown.
 */
export const CopyProvider = ({children}: {children: ReactNode}) => {
  const [message, setMessage] = useState<string | null>(null)
  const copy = useCallback<Copy>((value, what) => {
    setStringAsync(value).then(
      () => setMessage(`Copied the ${what}`),
      () => setMessage(`Could not copy the ${what}`)
    )
  }, [])
  const value = useMemo(() => copy, [copy])

  return (
    <CopyContext.Provider value={value}>
      <Box flex={1}>
        {children}
        <Snackbar
          duration="short"
          message={message ?? ''}
          offset="s96"
          onDismiss={() => setMessage(null)}
          visible={message !== null}
        />
      </Box>
    </CopyContext.Provider>
  )
}

export const useCopy = () => useContext(CopyContext)
