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
    linkType?: LinkType
    npcapHeader?: NpcapHeader
    payload?: EthernetPacket | NullPacket | IPv4 | SLLPacket

    constructor(
        public emitter?: EventEmitter,
    ) {}

    decode(packet: PacketData) {
        this.linkType = packet.linkType
        this.npcapHeader = new NpcapHeader(packet.header)

        const buffer = packet.buffer.subarray(0, this.npcapHeader.caplen)

        switch (this.linkType) {
            case 'LINKTYPE_ETHERNET':
                this.payload = new EthernetPacket(this.emitter).decode(buffer)
                break
            case 'LINKTYPE_NULL':
                this.payload = new NullPacket(this.emitter).decode(buffer)
                break
            case 'LINKTYPE_RAW':
                this.payload = new IPv4(this.emitter).decode(buffer)
                break
            case 'LINKTYPE_LINUX_SLL':
                this.payload = new SLLPacket(this.emitter).decode(buffer)
                break
            default:
                console.log(`[NpcapPacket] Unknown decode link type '${this.linkType}'.`)
        }

        return this
    }

    isEthernet(): this is NpcapDecode & { payload: EthernetPacket } {
        return this.linkType === 'LINKTYPE_ETHERNET'
    }

    isNull(): this is NpcapDecode & { payload: NullPacket } {
        return this.linkType === 'LINKTYPE_NULL'
    }

    isRaw(): this is NpcapDecode & { payload: IPv4 } {
        return this.linkType === 'LINKTYPE_RAW'
    }

    isSll(): this is NpcapDecode & { payload: SLLPacket } {
        return this.linkType === 'LINKTYPE_LINUX_SLL'
    }

    toString() {
        return `${this.linkType} ${this.payload}`
    }
}

export function decode(packet: PacketData, emitter?: EventEmitter) {
    return new NpcapDecode(emitter).decode(packet)
}
