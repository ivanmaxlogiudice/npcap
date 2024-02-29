import type { PacketData } from './types'
import { createSession } from '.'
import { decode } from './decode'

const session = createSession()
console.log(`Listening on ${session.device}, linkType: ${session.linkType}`)

session.on('packet', (data: PacketData) => {
    //                 ^?
    const packet = decode(data)
    console.log(packet.payload)
    //                   ^?
})
