import {adaptive, defineTheme} from '@hzblj/kara-ui'

/**
 * An emerald accent, the colour of a verified signature: every accent token is set in one place, and the Android seed
 * moves with them.
 */
export const theme = defineTheme({
  colors: {
    border: {accent: '#12a37f'},
    content: {accent: adaptive({dark: '#4fd1a8', light: '#0b7a5e'})},
    fill: {
      accent: {
        base: adaptive({dark: '#12a37f33', light: '#e3f6f0'}),
        disabled: adaptive({dark: '#12a37f1f', light: '#c3ebdf'}),
        primary: '#12a37f',
      },
    },
    shadow: {btn: {accent: {ring: adaptive({dark: '#12a37f00', light: '#a8e2d1'})}}},
  },
  materialSeed: '#12a37f',
})
