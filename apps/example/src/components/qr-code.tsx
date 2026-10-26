import qrcode from 'qrcode-generator'
import {useMemo} from 'react'
import {PixelRatio, StyleSheet, View} from 'react-native'

/** Modules of white around the code: the quiet zone a scanner needs to find it. */
const QUIET = 2

type Run = {readonly start: number; readonly length: number}

/** Each row's dark modules as runs, so a row is a handful of views rather than one per module. */
const runsOf = (value: string) => {
  const qr = qrcode(0, 'M')
  qr.addData(value)
  qr.make()
  const count = qr.getModuleCount()
  const rows: Run[][] = []

  for (let row = 0; row < count; row++) {
    const runs: Run[] = []
    let start = -1

    for (let column = 0; column <= count; column++) {
      const dark = column < count && qr.isDark(row, column)

      if (dark && start < 0) {
        start = column
      } else if (!dark && start >= 0) {
        runs.push({length: column - start, start})
        start = -1
      }
    }
    rows.push(runs)
  }

  return {count, rows}
}

/**
 * A QR code of `value`, black on white in both themes: scanners need the contrast, and a wallet's receive code is
 * scanned from another screen as often as from paper.
 */
export const QrCode = ({size, value}: {size: number; value: string}) => {
  const {count, rows} = useMemo(() => runsOf(value), [value])
  const cell = PixelRatio.roundToNearestPixel(size / (count + QUIET * 2))
  const side = cell * (count + QUIET * 2)

  return (
    <View accessibilityLabel={`QR code of ${value}`} accessible style={[styles.code, {height: side, width: side}]}>
      {rows.map((runs, row) =>
        runs.map(run => (
          <View
            key={`${row}:${run.start}`}
            style={[
              styles.module,
              {height: cell, left: (run.start + QUIET) * cell, top: (row + QUIET) * cell, width: run.length * cell},
            ]}
          />
        ))
      )}
    </View>
  )
}

const styles = StyleSheet.create({
  code: {backgroundColor: '#ffffff', borderRadius: 12},
  module: {backgroundColor: '#000000', position: 'absolute'},
})
