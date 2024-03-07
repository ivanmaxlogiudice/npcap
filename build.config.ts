import { resolve } from 'node:path'
import { defineBuildConfig } from 'unbuild'

export default defineBuildConfig({
    entries: ['src/index'],
    clean: true,
    declaration: true,
    rollup: {
        emitCJS: true,
    },
    alias: {
        '@': resolve(__dirname, './src'),
    },
    failOnWarn: false,
})
