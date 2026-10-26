import {AppState} from 'react-native'

import type {CreateAppSlice} from '../types'

export const appSlice: CreateAppSlice = set => ({
  appState: AppState.currentState,
  beginPrompt: () =>
    set(state => {
      state.prompting += 1
    }),
  endPrompt: () =>
    set(state => {
      state.prompting = Math.max(0, state.prompting - 1)
    }),
  prompting: 0,
  setAppState: appState =>
    set(state => {
      state.appState = appState
    }),
})
