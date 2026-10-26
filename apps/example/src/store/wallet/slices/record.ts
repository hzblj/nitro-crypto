import type {CreateRecordSlice} from '../types'

export const recordSlice: CreateRecordSlice = set => ({
  record: null,
  setRecord: record =>
    set(state => {
      state.record = record
    }),
})
