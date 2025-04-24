import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'
import { IPv4Addr } from './ipv4'

const typeVersion: Record<number, number> = {
    0x11: 3,
    0x12: 1,
    0x16: 2,
    0x17: 2,
    0x22: 3,
} as const

const typeMessage: Record<number, string> = {
    0x11: 'Membership Query',
    0x12: 'Membership Report',
    0x16: 'Membership Report',
    0x17: 'Leave Group',
    0x22: 'Membership Report',
}

export class IGMP {
    static decoderName = 'igmp'

    type: number
    maxResponseTime: number
    checksum: number
    groupAddress: IPv4Addr
    version: number = 0

    // IGMP v3
    // https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
    constructor(rawPacket: Buffer, offset: number = 0, emitter?: EventEmitter) {
        this.type = rawPacket[offset]
        this.maxResponseTime = rawPacket[offset + 1]
        this.checksum = rawPacket.readUInt16BE(offset + 2) // 2, 3
        this.groupAddress = new IPv4Addr(rawPacket, offset + 4) // 4, 5, 6, 7

        if (this.type in typeVersion)
            this.version = typeVersion[this.type]

        if (emitter)
            emitter.emit(IGMP.decoderName, this)
    }

    toString() {
        let ret

        if (this.type in typeMessage)
            ret = typeMessage[this.type]
        else
            ret = `type ${this.type}`

        return ret
    }
}
