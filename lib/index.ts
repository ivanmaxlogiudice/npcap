import { npcap } from './npcap'

console.log(npcap.libVersion())
console.log(npcap.findDevice('192.168.0.6'))
console.log(npcap.deviceList())
