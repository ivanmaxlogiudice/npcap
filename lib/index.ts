import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const addon = require('../build/Release/npcap.node')

console.log(addon.deviceList())
console.log(addon.findDevice('192.168.0.6'))
