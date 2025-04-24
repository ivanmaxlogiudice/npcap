import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'
import { HeaderExtension, ICMP, IGMP, IPv4, IPv6, NoNext, Tcp, Udp } from './protocols'

export type ProtocolsType =
    | HeaderExtension
    | ICMP
    | IGMP
    | IPv4
    | Tcp
    | Udp
    | IPv6
    | NoNext

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
export function protocols(protocol: number, emitter: EventEmitter | undefined, rawPacket: Buffer, offset: number, len: number = 0) {
    switch (protocol) {
        case 0:
            return new HeaderExtension(rawPacket, offset, emitter)
        case 1:
            return new ICMP(rawPacket, offset, emitter)
        case 2:
            return new IGMP(rawPacket, offset, emitter)
        case 4:
            return new IPv4(rawPacket, offset, emitter)
        case 6:
            return new Tcp(rawPacket, offset, len, emitter)
        case 17:
            return new Udp(rawPacket, offset, emitter)
        case 41:
            return new IPv6(rawPacket, offset, emitter)
        case 43:
        case 51:
            return new HeaderExtension(rawPacket, offset, emitter)
        case 59:
            return new NoNext(rawPacket, offset)
        case 60:
        case 135:
        case 139:
        case 140:
            return new HeaderExtension(rawPacket, offset, emitter)
    }

    throw new Error(`Dont know how to decode protocol ${protocol}`)
}
