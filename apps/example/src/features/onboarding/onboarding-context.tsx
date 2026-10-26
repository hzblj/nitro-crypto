import {createContext, type ReactNode, useContext, useMemo, useRef} from 'react'

import type {WalletRecord} from '../../store'

type Draft = {phrase: string; origin: WalletRecord['origin']}

type OnboardingValue = {
  readonly draft: () => Draft | null
  readonly setDraft: (draft: Draft | null) => void
}

const OnboardingContext = createContext<OnboardingValue | null>(null)

/**
 * The phrase between onboarding's steps, in memory and nowhere else: never in route params, which navigation state
 * keeps, logs and can restore. Gone when the flow closes.
 */
export const OnboardingProvider = ({children}: {children: ReactNode}) => {
  const draft = useRef<Draft | null>(null)
  const value = useMemo<OnboardingValue>(
    () => ({
      draft: () => draft.current,
      setDraft: next => {
        draft.current = next
      },
    }),
    []
  )

  return <OnboardingContext.Provider value={value}>{children}</OnboardingContext.Provider>
}

export const useOnboarding = (): OnboardingValue => {
  const value = useContext(OnboardingContext)
  if (!value) {
    throw new Error('useOnboarding needs an OnboardingProvider')
  }
  return value
}
