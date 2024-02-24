import config from '@ivanmaxlogiudice/eslint-config'

export default config(
    {},
    {
        files: ['.vscode/*'],
        rules: {
            'unicorn/filename-case': 'off',
        },
    },
    {
        rules: {
            'no-console': 'off',
            'unicorn/filename-case': 'off',
            'antfu/if-newline': 'off',
            'perfectionist/sort-classes': 'off',
        },
    },
)
