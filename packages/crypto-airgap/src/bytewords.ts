import {concatBytes, u32be} from './bytes'
import {crc32} from './crc32'
import {AirgapError} from './errors'

/**
 * The 256 Bytewords of BCR-2020-012, four letters each, in byte order. Each word's first and last letters are unique
 * to it, which is what lets the minimal style keep only those two.
 */
const WORDS =
  'ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcashcatschefcityclaw' +
  'codecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepicevenexam' +
  'exiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgoodgraygrimguru' +
  'gushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjadejazzjoinjoltjowl' +
  'judojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplionlistlogoloudloveluau' +
  'lucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobeyoboeomitonyxopenovalowls' +
  'paidpartpeckplaypluspoempoolposepuffpumapurrquadquizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascar' +
  'setssilkskewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuser' +
  'vastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszero' +
  'zestzinczonezoom'

/** `standard` separates whole words with spaces, `uri` with dashes; `minimal` keeps each word's first and last letter. */
export type BytewordsStyle = 'standard' | 'uri' | 'minimal'

const word = (byte: number) => WORDS.slice(byte * 4, byte * 4 + 4)

const LETTERS = 26

let lookup: Int16Array | undefined

/** Byte values by first and last letter, or -1 for a pair no word has. */
const byteTable = () => {
  if (!lookup) {
    lookup = new Int16Array(LETTERS * LETTERS).fill(-1)

    for (let byte = 0; byte < 256; byte++) {
      const text = word(byte)
      lookup[(text.charCodeAt(0) - 97) * LETTERS + (text.charCodeAt(3) - 97)] = byte
    }
  }

  return lookup
}

const invalid = (message: string) => new AirgapError('INVALID_UR', message)

const decodeWord = (text: string): number => {
  const first = text.charCodeAt(0) - 97
  const last = text.charCodeAt(text.length - 1) - 97

  if (first < 0 || first >= LETTERS || last < 0 || last >= LETTERS) {
    throw invalid('Bytewords are made of the letters a to z.')
  }

  const byte = byteTable()[first * LETTERS + last] ?? -1

  if (byte < 0 || (text.length === 4 && word(byte) !== text)) {
    throw invalid('A word is not one of the 256 Bytewords.')
  }

  return byte
}

const encode = (data: Uint8Array, style: BytewordsStyle = 'minimal'): string => {
  const words = Array.from(concatBytes(data, u32be(crc32(data))), byte =>
    style === 'minimal' ? `${word(byte)[0]}${word(byte)[3]}` : word(byte)
  )

  return words.join(style === 'standard' ? ' ' : style === 'uri' ? '-' : '')
}

const split = (text: string, style: BytewordsStyle): string[] => {
  if (style === 'minimal') {
    if (text.length % 2 !== 0) {
      throw invalid('Minimal Bytewords come in pairs of letters.')
    }

    return Array.from({length: text.length / 2}, (_, index) => text.slice(index * 2, index * 2 + 2))
  }

  const words = text.split(style === 'standard' ? ' ' : '-')

  if (words.some(item => item.length !== 4)) {
    throw invalid('Bytewords are four letters each.')
  }

  return words
}

const decode = (text: string, style: BytewordsStyle = 'minimal'): Uint8Array => {
  const bytes = Uint8Array.from(split(text.toLowerCase(), style), decodeWord)

  if (bytes.length < 5) {
    throw invalid('Bytewords carry at least one byte and a four-byte checksum.')
  }

  const body = bytes.subarray(0, -4)
  const expected = new DataView(bytes.buffer, bytes.length - 4, 4).getUint32(0, false)

  if (crc32(body) !== expected) {
    throw invalid('The Bytewords checksum does not match: the text was misread or altered.')
  }

  return body.slice()
}

/**
 * Bytewords (BCR-2020-012): bytes as English words with a CRC-32 checksum appended. `decode` takes either case and
 * throws `INVALID_UR` for a word that is not one, or a checksum that does not match.
 */
export const bytewords = Object.freeze({decode, encode})
