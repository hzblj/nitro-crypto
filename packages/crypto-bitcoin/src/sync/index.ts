/**
 * `@hzblj/crypto-bitcoin/sync`: a watch-only Bitcoin account kept in sync with a backend over `fetch` (Esplora by
 * default). Apart from the package's main entry, which stays free of network code: an app that only signs never
 * loads this.
 */
export type {
  AccountAddress,
  AccountBalance,
  AccountTransaction,
  AccountUtxo,
  AccountView,
  AddressUsage,
} from './accounting'
export type {
  AddressSummary,
  BackendInput,
  BackendOutput,
  BackendStatus,
  BackendTransaction,
  BitcoinBackend,
  BlockRef,
  FeeEstimates,
  HistoryPage,
} from './backend'
export {isSyncError, SYNC_ERROR_CODES, SyncError, type SyncErrorCode} from './errors'
export {ESPLORA_URLS, type EsploraOptions, esploraBackend} from './esplora'
export {type ExtendedKeyNetwork, formatExtendedKey, type ParsedExtendedKey, parseExtendedKey} from './extended-key'
export type {HttpOptions, RequestOptions} from './http'
export type {ScriptType} from './script-types'
export type {SnapshotAddress, SnapshotSummary, SnapshotTransaction, SyncSnapshot} from './state'
export {
  type BitcoinSync,
  type BitcoinSyncOptions,
  createBitcoinSync,
  type Payment,
  type PaymentRequest,
  type PsbtOptions,
  type SyncOptions,
  type SyncSource,
  type TransactionStatus,
} from './sync'
