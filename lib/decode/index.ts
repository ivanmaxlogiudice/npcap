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

export interface PacketByType {
    LINKTYPE_ETHERNET: EthernetPacket
    LINKTYPE_NULL: NullPacket
    LINKTYPE_RAW: IPv4
    LINKTYPE_LINUX_SLL: SLLPacket
}

export type NcapPacket = {
    [T in LinkType]: {
        linkType: T
        npcapHeader: NpcapHeader
        payload: PacketByType[T]
    }
}[LinkType]

export function decode<T extends LinkType>(packet: PacketData & { linkType: T }, emitter?: EventEmitter): NcapPacket & { linkType: T } {
    const npcapHeader = new NpcapHeader(packet.header)
    const buffer = packet.buffer.subarray(0, npcapHeader.caplen)

    switch (packet.linkType) {
        case 'LINKTYPE_ETHERNET':
            return {
                npcapHeader,
                linkType: packet.linkType,
                payload: new EthernetPacket(emitter).decode(buffer),
            }
        case 'LINKTYPE_NULL':
            return {
                npcapHeader,
                linkType: packet.linkType,
                payload: new NullPacket(emitter).decode(buffer),
            }
        case 'LINKTYPE_RAW':
            return {
                npcapHeader,
                linkType: packet.linkType,
                payload: new IPv4(emitter).decode(buffer),
            }
        case 'LINKTYPE_LINUX_SLL':
            return {
                npcapHeader,
                linkType: packet.linkType,
                payload: new SLLPacket(emitter).decode(buffer),
            }
        default:
            throw new Error(`[NpcapPacket] Unknown decode link type '${packet.linkType}'.`)
    }
}
