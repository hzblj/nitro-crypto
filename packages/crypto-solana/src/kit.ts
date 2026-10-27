/**
 * `@hzblj/crypto-solana/kit`: an account as a @solana/kit signer. Only types come from kit (an optional peer
 * dependency), so this entry loads nothing of it, and the main entry never imports this one.
 */
import type {
  Address,
  MessagePartialSigner,
  MessagePartialSignerConfig,
  SignableMessage,
  SignatureBytes,
  SignatureDictionary,
  Transaction,
  TransactionPartialSigner,
  TransactionPartialSignerConfig,
} from '@solana/kit'

import type {SolanaAccount} from './account'

/** What `toKitSigner` returns: a partial signer of transactions and of messages, as kit's key pair signers are. */
export type SolanaKitSigner = TransactionPartialSigner & MessagePartialSigner

/** The part of an account a kit signer uses. Any `SolanaAccount` has it. */
export type SolanaKitSignerAccount = Pick<SolanaAccount, 'address' | 'signMessage' | 'signTransactionMessage'>

/**
 * The account as a kit `TransactionPartialSigner` and `MessagePartialSigner`, its key still in the engine: give it to
 * `setTransactionMessageFeePayerSigner`, put it in an instruction's account metas, and let
 * `signTransactionMessageWithSigners`, `partiallySignTransactionMessageWithSigners` or
 * `signOffchainMessageWithSigners` ask it for signatures. Ed25519 is deterministic, so the signatures are those a kit
 * key pair signer makes with the same key.
 *
 * - `signTransactions` signs each transaction's message (legacy or v0) after reading it, and refuses
 *   (`INVALID_ARGUMENT`) one this account is not a signer of, as kit's signers do.
 * - `signMessages` signs each message's bytes as they are, as kit's key pair signers do: plain messages, and
 *   off-chain message envelopes, whose content is the encoded off-chain message.
 *
 * An aborted `abortSignal` stops it before the next signature.
 */
export const toKitSigner = (account: SolanaKitSignerAccount): SolanaKitSigner => {
  const address = account.address as Address
  const signed = (signature: Uint8Array): SignatureDictionary => Object.freeze({[address]: signature as SignatureBytes})

  return Object.freeze({
    address,
    signMessages: async (messages: readonly SignableMessage[], config?: MessagePartialSignerConfig) => {
      const out: SignatureDictionary[] = []

      for (const message of messages) {
        config?.abortSignal?.throwIfAborted()
        out.push(signed(await account.signMessage({message: message.content})))
      }

      return Object.freeze(out)
    },
    signTransactions: async (transactions: readonly Transaction[], config?: TransactionPartialSignerConfig) => {
      const out: SignatureDictionary[] = []

      for (const transaction of transactions) {
        config?.abortSignal?.throwIfAborted()
        out.push(signed(await account.signTransactionMessage(Uint8Array.from(transaction.messageBytes))))
      }

      return Object.freeze(out)
    },
  })
}
