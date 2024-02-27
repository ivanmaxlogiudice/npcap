import { Buffer } from 'node:buffer'
import * as npcap from './lib'

console.log(npcap.npcap.deviceList())
console.log(npcap.npcap.defaultDevice())

// const session = npcap.createSession('\\Device\\NPF_{56761211-7574-48DB-952D-1E8C714F31E6}')
// console.log(`Listening on ${session.device}, linkType: ${session.linkType}`)
// session.on('packet', (data) => {
//     const packet = npcap.decode(data)
//     if (packet.linkType !== 'ETHERNET')
//         return

//     // console.log(packet)
// })

// setTimeout(() => console.log(session.inject(Buffer.from([0x00]))), 5_000)

// setTimeout(() => {
//     console.log('Close connection')
//     session.close()
// }, 10_000)
