import { createSession, decode } from '../lib'

// On empty device will try to get default device.
const session = createSession('', { filter: 'tcp' })
console.log(`Listening on ${session.device}`)

session.on('packet', (data) => {
    const packet = decode(data)

    // Check if its ETHERNET and IPv4.
    if (!packet.isEthernet() || !packet.payload.isIPv4())
        return

    console.log(packet.payload.payload)
})
