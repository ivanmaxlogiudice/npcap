import { config } from '@ivanmaxlogiudice/eslint-config'

export default config({
    typescript: true,
}, {
    rules: {
        'no-console': 'off',
        'antfu/if-newline': 'off',
    },
})
