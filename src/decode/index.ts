import type { LinkType, PacketData } from '@/types'
import { EthernetPacket, NullPacket, SLLPacket } from './packets'
import { IPv4 } from './protocols'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class NpcapHeader {
    caplen: number
    len: number
    tvSec: number
    tvUsec: number

    constructor(rawHeader: Buffer) {
        this.tvSec = rawHeader.readUInt32LE(0)
        this.tvUsec = rawHeader.readUInt32LE(4)
        this.caplen = rawHeader.readUInt32LE(8)
        this.len = rawHeader.readUInt32LE(12)
    }
}

export class NpcapDecode {
    linkType: LinkType
    npcapHeader: NpcapHeader
    payload: EthernetPacket | NullPacket | IPv4 | SLLPacket

    constructor(packet: PacketData, emitter?: EventEmitter) {
        this.linkType = packet.linkType
        this.npcapHeader = new NpcapHeader(packet.header)

        const buffer = packet.buffer.subarray(0, this.npcapHeader.caplen)

        switch (this.linkType) {
            case 'LINKTYPE_ETHERNET':
                this.payload = new EthernetPacket(buffer, 0, emitter)
                break
            case 'LINKTYPE_NULL':
                this.payload = new NullPacket(buffer, 0, emitter)
                break
            case 'LINKTYPE_RAW':
                this.payload = new IPv4(buffer, 0, emitter)
                break
            case 'LINKTYPE_LINUX_SLL':
                this.payload = new SLLPacket(buffer, 0, emitter)
                break
            default:
                throw new Error(`[NpcapPacket] Unknown decode link type '${this.linkType}'.`)
        }

        return this
    }

    isEthernet(): this is { payload: EthernetPacket } {
        return this.payload instanceof EthernetPacket
    }

    isNull(): this is { payload: NullPacket } {
        return this.payload instanceof NullPacket
    }

    isIPv4(): this is { payload: IPv4 } {
        return this.payload instanceof IPv4
    }

    isSLL(): this is { payload: SLLPacket } {
        return this.payload instanceof SLLPacket
    }

    toString() {
        return `${this.linkType} ${this.payload}`
    }
}

export function decode(packet: PacketData, emitter?: EventEmitter) {
    return new NpcapDecode(packet, emitter)
}
