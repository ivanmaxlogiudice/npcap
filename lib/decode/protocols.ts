import { ICMP } from './protocols/icmp'
import { IGMP } from './protocols/igmp'
import { IPv4 } from './protocols/ipv4'
import { IPv6 } from './protocols/ipv6'
import { Tcp } from './protocols/tcp'
import { Udp } from './protocols/udp'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export function protocols(protocol: number, emitter: EventEmitter | undefined, rawPacket: Buffer, offset: number, len: number = 0) {
    switch (protocol) {
        case 1:
            return new ICMP(emitter).decode(rawPacket, offset)
        case 2:
            return new IGMP(emitter).decode(rawPacket, offset)
        case 4:
            return new IPv4(emitter).decode(rawPacket, offset)
        case 6:
            return new Tcp(emitter).decode(rawPacket, offset, len)
        case 17:
            return new Udp(emitter).decode(rawPacket, offset)
        case 41:
            return new IPv6(emitter).decode(rawPacket, offset)
    }

    return undefined
}
