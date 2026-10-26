import {Stack} from 'expo-router'

import {AboutScreen} from '../../../src/features/debug/about'

export default function About() {
  return (
    <>
      <Stack.Screen options={{title: 'About and security'}} />
      <AboutScreen />
    </>
  )
}
