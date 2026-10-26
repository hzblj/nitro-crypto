import type {CreateSettingsSlice} from '../types'

export const settingsSlice: CreateSettingsSlice = set => ({
  autoLock: 'minute',
  setAutoLock: autoLock =>
    set(state => {
      state.autoLock = autoLock
    }),
})
