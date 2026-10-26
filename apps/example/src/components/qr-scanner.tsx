import {Box, Button, Island, RnText, TextField, VStack} from '@hzblj/kara-ui'
import {CameraView, useCameraPermissions} from 'expo-camera'
import {StyleSheet} from 'react-native'

type QrScannerProps = {
  /** Every QR code the camera reads, as text, each time it reads it: the caller ignores repeats. */
  onScan: (text: string) => void
  /** Pauses the camera's reading without unmounting it. */
  paused?: boolean
  size: number
  testID?: string
}

/** Text that is a UR, in either case: what the paste field hands on, and nothing it is still being typed into. */
const UR_TEXT = /^ur:[a-z0-9-]+\/\S+$/i

/**
 * The camera, reading QR codes, with the permission it needs asked for in place. A UR can be pasted instead, into a
 * field (no clipboard prompt: the paste is the user's own): a simulator has no camera, and a desktop wallet can copy
 * one.
 */
export const QrScanner = ({onScan, paused = false, size, testID}: QrScannerProps) => {
  const [permission, requestPermission] = useCameraPermissions()

  const paste = (text: string) => {
    const trimmed = text.trim()

    if (UR_TEXT.test(trimmed)) {
      onScan(trimmed)
    }
  }

  return (
    // A React Native column: the camera is a React Native view, and SwiftUI's stack (`VStack`) takes only native
    // children. The buttons below are native, in their own `Island`.
    <Box gap="s12" testID={testID} w={size}>
      {permission?.granted ? (
        <Box borderRadius="large" h={size} overflow="hidden" w={size}>
          <CameraView
            barcodeScannerSettings={{barcodeTypes: ['qr']}}
            facing="back"
            onBarcodeScanned={paused ? undefined : ({data}) => onScan(data)}
            style={StyleSheet.absoluteFill}
          />
        </Box>
      ) : (
        <Box
          align="center"
          bg="surface.primary"
          borderRadius="large"
          gap="s12"
          h={size}
          justify="center"
          p="s20"
          w={size}
        >
          <RnText align="center" color="content.secondary" variant="subheadline">
            {permission?.canAskAgain === false
              ? 'Camera access is off for this app: turn it on in Settings to scan.'
              : 'Scanning needs the camera. Nothing it sees leaves this device.'}
          </RnText>
        </Box>
      )}
      <Island>
        <VStack spacing="s12" wide>
          {permission?.granted ? null : (
            <Button
              disabled={permission?.canAskAgain === false}
              label="Allow the camera"
              onPress={requestPermission}
              testID="allow-camera"
            />
          )}
          <TextField label="Or paste a UR" onChangeText={paste} testID="paste-ur" />
        </VStack>
      </Island>
    </Box>
  )
}
