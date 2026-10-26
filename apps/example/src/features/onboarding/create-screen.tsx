import {Button, Island, Pressable, RnIcon, RnText, SegmentedControl} from '@hzblj/kara-ui'
import {useRouter} from 'expo-router'
import {useState} from 'react'

import {Lead, Notice, Page, PhraseGrid} from '../../components'
import {generatePhrase} from '../../core'
import {useOnboarding} from './onboarding-context'

const LENGTHS = [12, 24] as const

/** Step one of a new wallet: the engine draws a phrase from the OS CSPRNG, and the person writes it down. */
export const CreateScreen = () => {
  const router = useRouter()
  const {setDraft} = useOnboarding()
  const [length, setLength] = useState(0)
  const [phrase, setPhrase] = useState(() => generatePhrase(12))
  const [revealed, setRevealed] = useState(false)
  const words = phrase.split(' ')

  const regenerate = (index: number) => {
    setLength(index)
    setPhrase(generatePhrase(LENGTHS[index] ?? 12))
    setRevealed(false)
  }

  const next = () => {
    setDraft({origin: 'created', phrase})
    router.push('/onboarding/protect')
  }

  return (
    <Page testID="onboarding-create">
      <Lead>
        Your recovery phrase is the wallet. Write the words down in order, on paper, and keep them where only you can
        reach them. This device can break or get lost; the words cannot.
      </Lead>
      <SegmentedControl onChange={regenerate} selectedIndex={length} values={LENGTHS.map(count => `${count} words`)} />
      {revealed ? (
        <PhraseGrid testID="phrase" words={words} />
      ) : (
        <Pressable
          accessibilityLabel="Show the recovery phrase"
          align="center"
          bg="surface.primary"
          borderRadius="large"
          gap="s12"
          onPress={() => setRevealed(true)}
          p="s32"
          testID="reveal-phrase"
        >
          <RnIcon color="content.secondary" name="visibility" size="s32" />
          <RnText align="center" variant="headline">
            Tap to show your phrase
          </RnText>
          <RnText align="center" color="content.secondary" variant="footnote">
            Make sure nobody is looking, and nothing is recording the screen.
          </RnText>
        </Pressable>
      )}
      <Notice
        text="Generated inside the Zig engine from the operating system's randomness. It leaves the engine once, for you to write down."
        tone="neutral"
      />
      <Island>
        <Button disabled={!revealed} label="I wrote it down" onPress={next} testID="wrote-it-down" />
      </Island>
    </Page>
  )
}
