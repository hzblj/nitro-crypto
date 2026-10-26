import {Stack} from 'expo-router'

import {RecoveryPhraseScreen} from '../../../src/features/settings'

export default function RecoveryPhrase() {
  return (
    <>
      <Stack.Screen options={{title: 'Recovery phrase'}} />
      <RecoveryPhraseScreen />
    </>
  )
}
