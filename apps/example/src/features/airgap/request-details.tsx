import type {BitcoinSignRequest, BitcoinSignWarning} from '@hzblj/crypto-airgap-bitcoin'
import type {EthereumSignRequest, EthereumSignWarning} from '@hzblj/crypto-airgap-ethereum'
import type {SolanaSignRequest, SolanaSignWarning} from '@hzblj/crypto-airgap-solana'
import type {SolanaInstructionSummary} from '@hzblj/crypto-solana'
import {Box, Island, LabeledContent, RnText} from '@hzblj/kara-ui'
import {hex} from '@hzblj/nitro-crypto'
import {Fragment} from 'react'

import {Card, Notice, RowDivider, Rows, Value} from '../../components'
import {NETWORKS} from '../../config'
import type {ScannedRequest} from '../../core'
import {formatUnits, shortAddress} from '../../utils'

const BITCOIN_WARNINGS: Record<BitcoinSignWarning, string> = {
  FOREIGN_INPUTS: 'Some inputs spend coins of other keys. This wallet signs only its own.',
  NO_ADDRESS_OUTPUT: 'An output pays a script with no address: it may carry data, or lock coins in a custom way.',
  UNKNOWN_FEE: 'An input does not say how much it holds, so the fee is unknown.',
  UNVERIFIED_VALUES:
    "Some coins come without their previous transaction: their values, and so the fee, are the requesting wallet's word.",
}

const ETHEREUM_WARNINGS: Record<EthereumSignWarning, string> = {
  ALL_CHAINS_DELEGATION: 'A delegation is valid on every chain, not only this one.',
  CONTRACT_CREATION: 'This deploys a new contract from code this wallet cannot describe.',
  DELEGATION: 'This lets a contract act for an account. Sign only if you trust that contract.',
  NO_CHAIN_ID: 'The data names no chain: its signature is valid on every network.',
}

const SOLANA_WARNINGS: Record<SolanaSignWarning, string> = {
  NOT_FEE_PAYER: 'Another account pays the fee: this wallet only adds its signature.',
  OTHER_SIGNERS: 'Other accounts must sign too, which this wallet cannot do for them.',
  UNKNOWN_INSTRUCTIONS:
    'An instruction calls a program this wallet cannot describe. Sign only if you know what it does.',
  UNRESOLVED_LOOKUPS: 'Some accounts come from lookup tables this wallet cannot read offline.',
}

/** Typed data's values as text: bigints as decimal digits, nested structs indented. */
const typedDataText = (value: unknown) =>
  JSON.stringify(value, (_, entry) => (typeof entry === 'bigint' ? entry.toString() : entry), 2)

/** The amount a request moves, large, the way the send screen shows its own. */
const Headline = ({label, value}: {label: string; value: string}) => (
  <Box align="center" gap="s4" testID="airgap-headline">
    <RnText color="content.secondary" variant="subheadline">
      {label}
    </RnText>
    <RnText align="center" monospacedDigit variant="headingL">
      {value}
    </RnText>
  </Box>
)

const Warnings = ({warnings}: {warnings: readonly string[]}) =>
  warnings.length === 0 ? null : (
    <Box gap="s8">
      {warnings.map(text => (
        <Notice key={text} text={text} tone="warning" />
      ))}
    </Box>
  )

const MessageDetails = ({message, text}: {message: Uint8Array; text?: string}) => (
  <>
    <Headline label="Sign a message" value={text === undefined ? `${message.length} bytes` : 'Text'} />
    <Card>
      <Value label={text === undefined ? 'Bytes' : 'Message'} value={text ?? hex.encode(message, {prefix: true})} />
    </Card>
    <RnText color="content.tertiary" variant="footnote">
      A signature proves this wallet holds the address. Read the message: some sign-ins authorize more than they say.
    </RnText>
  </>
)

const BitcoinDetails = ({request}: {request: BitcoinSignRequest}) => (
  <>
    <Headline label="Send" value={`${formatUnits(request.sending, 8, 8)} BTC`} />
    <Card>
      {request.outputs.map((output, index) => (
        <Value
          // Outputs are positional, and may repeat an address: the index is their identity.
          key={index}
          label={output.change ? 'Change, back to this wallet' : `To, ${formatUnits(output.value, 8, 8)} BTC`}
          value={output.address ?? hex.encode(output.scriptPubKey)}
        />
      ))}
    </Card>
    <Island>
      <Rows>
        <LabeledContent
          label="Network fee"
          value={request.fee === undefined ? 'Unknown' : `${formatUnits(request.fee, 8, 8)} BTC`}
        />
        <RowDivider />
        <LabeledContent
          label="Coins spent"
          value={`${request.inputs.filter(input => input.mine).length} of ${request.inputs.length}, ${formatUnits(request.spending, 8, 8)} BTC`}
        />
        <RowDivider />
        <LabeledContent label="Transaction" value={shortAddress(request.txid, 10, 6)} />
      </Rows>
    </Island>
    <Warnings warnings={request.warnings.map(warning => BITCOIN_WARNINGS[warning])} />
  </>
)

/** Which of the account's keys signs: a wallet paired with the account key may ask for any of its addresses. */
const EthereumSigner = ({request}: {request: EthereumSignRequest}) => (
  <Island>
    <Rows>
      <LabeledContent label="Signed with" testID="airgap-signer-path" value={request.path} />
      {request.address ? (
        <>
          <RowDivider />
          <LabeledContent label="Address" value={shortAddress(request.address)} />
        </>
      ) : null}
    </Rows>
  </Island>
)

const EthereumDetails = ({request}: {request: EthereumSignRequest}) => {
  if (request.kind === 'message') {
    return (
      <>
        <MessageDetails message={request.message} text={request.text} />
        <EthereumSigner request={request} />
      </>
    )
  }

  if (request.kind === 'typed-data') {
    const {domain, message, primaryType} = request.typedData

    return (
      <>
        <Headline label="Sign typed data" value={primaryType} />
        <Card>
          {domain?.name ? <Value label="App" value={domain.name} /> : null}
          {domain?.verifyingContract ? <Value label="Contract" value={domain.verifyingContract} /> : null}
          <Value label="Chain id" value={domain?.chainId === undefined ? 'None' : String(domain.chainId)} />
          <Value label="Message" value={typedDataText(message)} />
        </Card>
        <EthereumSigner request={request} />
        <Warnings warnings={request.warnings.map(warning => ETHEREUM_WARNINGS[warning])} />
      </>
    )
  }

  const {authorizations, erc20Transfer, maxFee, transaction} = request
  const to = transaction.to
  const token =
    to === null ? undefined : NETWORKS.ethereum.tokens.find(entry => entry.contract?.toLowerCase() === to.toLowerCase())

  return (
    <>
      <Headline
        label={erc20Transfer ? 'Send tokens' : to === null ? 'Deploy a contract' : 'Send'}
        value={
          erc20Transfer
            ? token
              ? `${formatUnits(erc20Transfer.amount, token.decimals, token.decimals)} ${token.symbol}`
              : `${erc20Transfer.amount} units`
            : `${formatUnits(transaction.value ?? 0n, 18, 8)} ETH`
        }
      />
      <Card>
        <Value label="To" value={erc20Transfer ? erc20Transfer.recipient : (to ?? 'A new contract')} />
        {erc20Transfer && to !== null ? (
          <Value label={token ? `${token.symbol} contract` : 'Token contract'} value={to} />
        ) : null}
        {authorizations.map((authorization, index) => (
          <Value
            // Authorizations are positional: the index is their identity.
            key={index}
            label={`Delegates ${authorization.authority ? shortAddress(authorization.authority) : 'an unknown account'}`}
            value={authorization.address}
          />
        ))}
        {!erc20Transfer && transaction.data !== '0x' ? <Value label="Call data" value={transaction.data} /> : null}
      </Card>
      <Island>
        <Rows>
          <LabeledContent label="Network fee, at most" value={`${formatUnits(maxFee, 18, 8)} ETH`} />
          <RowDivider />
          <LabeledContent label="Chain id" value={String(transaction.chainId)} />
          <RowDivider />
          <LabeledContent label="Nonce" value={String(transaction.nonce)} />
          <RowDivider />
          <LabeledContent label="Gas limit" value={String(transaction.gas)} />
        </Rows>
      </Island>
      <EthereumSigner request={request} />
      {!erc20Transfer && to !== null && transaction.data !== '0x' ? (
        <Notice text="This calls a contract with data this wallet cannot describe." tone="warning" />
      ) : null}
      <Warnings warnings={request.warnings.map(warning => ETHEREUM_WARNINGS[warning])} />
    </>
  )
}

const describeInstruction = (summary: SolanaInstructionSummary): string => {
  switch (summary.type) {
    case 'transfer':
      return `Send ${formatUnits(summary.lamports, 9, 9)} SOL to ${shortAddress(summary.to)}`
    case 'token-transfer':
      return `Send ${formatUnits(summary.amount, summary.decimals, summary.decimals)} of ${shortAddress(summary.mint)} to ${shortAddress(summary.destination)}`
    case 'create-token-account':
      return `Create a token account for ${shortAddress(summary.owner)}`
    case 'compute-unit-limit':
      return `Compute limit: ${summary.units} units`
    case 'compute-unit-price':
      return `Priority fee: ${summary.microLamports} micro-lamports a unit`
    default:
      return `Call ${shortAddress(summary.programId)}`
  }
}

const SolanaDetails = ({request}: {request: SolanaSignRequest}) => {
  if (request.kind === 'message') {
    return <MessageDetails message={request.message} text={request.text} />
  }

  if (request.kind === 'offchain-message') {
    return (
      <>
        <MessageDetails message={request.message} text={request.decoded.text} />
        <Island>
          <Rows>
            <LabeledContent label="Off-chain message" value={`Version ${request.decoded.version}`} />
            <RowDivider />
            <LabeledContent label="Signers" value={String(request.decoded.signers.length)} />
          </Rows>
        </Island>
        <Warnings warnings={request.warnings.map(warning => SOLANA_WARNINGS[warning])} />
      </>
    )
  }

  return (
    <>
      <Headline label="Send" value={`${formatUnits(request.lamports, 9, 9)} SOL`} />
      <Island>
        <Rows>
          {request.decoded.instructions.map((instruction, index) => (
            // Instructions are positional, and may repeat: the index is their identity.
            <Fragment key={index}>
              {index > 0 ? <RowDivider /> : null}
              <LabeledContent label={describeInstruction(instruction.summary)} />
            </Fragment>
          ))}
        </Rows>
      </Island>
      <Island>
        <Rows>
          <LabeledContent label="Fee payer" value={shortAddress(request.decoded.feePayer)} />
          <RowDivider />
          <LabeledContent label="Signers" value={String(request.decoded.signers.length)} />
          <RowDivider />
          <LabeledContent label="Recent blockhash" value={shortAddress(request.decoded.recentBlockhash)} />
        </Rows>
      </Island>
      <Warnings warnings={request.warnings.map(warning => SOLANA_WARNINGS[warning])} />
    </>
  )
}

/** What a scanned request asks, read from the bytes that will be signed: the screen to read before agreeing. */
export const RequestDetails = ({scanned}: {scanned: ScannedRequest}) => {
  switch (scanned.chain) {
    case 'bitcoin':
      return <BitcoinDetails request={scanned.request} />
    case 'ethereum':
      return <EthereumDetails request={scanned.request} />
    default:
      return <SolanaDetails request={scanned.request} />
  }
}
