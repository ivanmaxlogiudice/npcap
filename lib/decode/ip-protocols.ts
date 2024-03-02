import { HeaderExtension, ICMP, IGMP, IPv4, IPv6, NoNext, Tcp, Udp } from './protocols'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

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
            return new HeaderExtension().decode(rawPacket, offset)
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
        case 43:
        case 51:
            return new HeaderExtension().decode(rawPacket, offset)
        case 59:
            return new NoNext().decode(rawPacket, offset)
        case 60:
        case 135:
        case 139:
        case 140:
            return new HeaderExtension().decode(rawPacket, offset)
    }

    return undefined
}
