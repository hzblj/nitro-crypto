import {Stack} from 'expo-router'

import {AboutScreen} from '../../../src/about'

export default function About() {
  return (
    <>
      <Stack.Screen options={{title: 'About and security'}} />
      <AboutScreen />
    </>
  )
}
