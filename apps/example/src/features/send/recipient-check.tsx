import {Box, RnIcon, RnText} from '@hzblj/kara-ui'
import {NETWORKS} from '../../config'
import {type ChainId, walletCrypto} from '../../core'

export type RecipientCheck = {readonly valid: boolean; readonly text: string; readonly normalized?: string}

/** The adapter's verdict on an address, in words: the same `validateAddress` the transaction builder relies on. */
export const useRecipientCheck = (chain: ChainId, address: string): RecipientCheck | null => {
  const crypto = walletCrypto()
  const trimmed = address.trim()

  if (!crypto || trimmed === '') {
    return null
  }

  const network = NETWORKS[chain]
  const result = crypto.chains[chain].validateAddress(trimmed)

  if (!result.valid) {
    return {text: result.reason, valid: false}
  }

  const kind =
    'type' in result && typeof result.type === 'string'
      ? ` (${result.type.toUpperCase()})`
      : 'checksum' in result && result.checksum === 'valid'
        ? ' (EIP-55 checksum)'
        : ''

  return {normalized: result.normalized, text: `A ${network.name} ${network.testnet} address${kind}`, valid: true}
}

export const RecipientVerdict = ({check}: {check: RecipientCheck}) => (
  <Box align="center" gap="s6" row testID="recipient-check">
    <RnIcon
      color={check.valid ? 'content.success' : 'content.destructive'}
      name={check.valid ? 'check-circle-filled' : 'error'}
      size="s16"
    />
    <RnText color={check.valid ? 'content.secondary' : 'content.destructive'} fill variant="footnote">
      {check.text}
    </RnText>
  </Box>
)
