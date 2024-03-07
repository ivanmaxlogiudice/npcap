import path from 'node:path'
import { defineConfig } from 'vitest/config'

export default defineConfig({
    test: {
        coverage: {
            exclude: ['examples'],
        },
    },
    resolve: {
        alias: [
            { find: '@', replacement: path.resolve(__dirname, 'src') },
        ],
    },
})
