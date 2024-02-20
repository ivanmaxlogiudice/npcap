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
        'no-console': 'off',
    },
)
