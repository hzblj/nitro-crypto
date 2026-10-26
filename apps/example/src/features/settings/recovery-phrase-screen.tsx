import {Button, Island} from '@hzblj/kara-ui'
import {useFocusEffect} from 'expo-router'
import {useCallback, useState} from 'react'

import {Lead, Notice, Page, PhraseGrid} from '../../components'
import {revealPhrase} from '../../core'

/** The stored phrase, after Face ID, for as long as this screen is in front: leaving it forgets the words. */
export const RecoveryPhraseScreen = () => {
  const [words, setWords] = useState<string[] | null>(null)
  const [problem, setProblem] = useState<string | null>(null)

  useFocusEffect(useCallback(() => () => setWords(null), []))

  const reveal = async () => {
    setProblem(null)
    const read = await revealPhrase()
    if (read.status === 'ok') {
      setWords(read.phrase.split(' '))
    } else if (read.status === 'failed') {
      setProblem(read.message)
    } else if (read.status === 'lost') {
      setProblem('The Keychain no longer has it. Use the copy you wrote down.')
    }
  }

  return (
    <Page testID="recovery-phrase">
      <Lead>
        These words are the wallet. Anyone who reads them can take everything on every chain, from any device.
      </Lead>
      <Notice
        text="Never type them into a website, a chat or a support form. No one legitimate will ever ask for them."
        title="Keep them offline"
        tone="warning"
      />
      {problem ? <Notice text={problem} tone="destructive" /> : null}
      {words ? (
        <>
          <PhraseGrid testID="recovery-words" words={words} />
          <Island>
            <Button label="Hide" onPress={() => setWords(null)} variant="secondary" />
          </Island>
        </>
      ) : (
        <Island>
          <Button label="Show recovery phrase" onPress={reveal} testID="reveal-phrase" />
        </Island>
      )}
    </Page>
  )
}
