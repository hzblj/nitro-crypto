import {createMultipartEncoder, type Sha256, type UR} from '@hzblj/crypto-airgap'
import {Box, RnText} from '@hzblj/kara-ui'
import {useEffect, useMemo, useState} from 'react'

import {QrCode} from './qr-code'

type AnimatedQrProps = {
  ur: UR
  /** The engine's `crypto.hash.sha256`: the fountain code seeds its choice of fragments with it. */
  sha256: Sha256
  size: number
  /** Milliseconds per part: long enough for a camera to focus on each. */
  interval?: number
  /** Bytes per part: smaller parts make simpler codes, which cameras read from farther away. */
  maxFragmentLength?: number
  testID?: string
}

/**
 * A UR as a QR code: one code when it fits, else its multipart parts in turn, fountain-coded, so a scanner that
 * misses some catches up from the next. The timer is here, in the app; the library only hands out the next part.
 */
export const AnimatedQr = ({interval = 250, maxFragmentLength = 120, sha256, size, testID, ur}: AnimatedQrProps) => {
  const encoder = useMemo(
    () => createMultipartEncoder(ur, {maxFragmentLength, sha256}),
    [ur, maxFragmentLength, sha256]
  )
  const [part, setPart] = useState(() => encoder.nextPart().toUpperCase())

  useEffect(() => {
    setPart(encoder.nextPart().toUpperCase())

    if (encoder.isSinglePart) {
      return
    }

    const timer = setInterval(() => setPart(encoder.nextPart().toUpperCase()), interval)

    return () => clearInterval(timer)
  }, [encoder, interval])

  return (
    <Box align="center" gap="s8" testID={testID}>
      <QrCode level="L" mode="Alphanumeric" size={size} value={part} />
      <RnText color="content.tertiary" monospacedDigit variant="footnote">
        {encoder.isSinglePart
          ? `${ur.type}, ${ur.cbor.length} bytes`
          : `${ur.type}, ${ur.cbor.length} bytes in ${encoder.fragmentCount} parts, part ${encoder.seqNum}`}
      </RnText>
    </Box>
  )
}
