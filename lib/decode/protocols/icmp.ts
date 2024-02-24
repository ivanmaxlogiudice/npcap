import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

const typeMessage: Record<number, string> = {
    0: 'Echo Reply',
    1: 'Reserved',
    2: 'Reserved',
    4: 'Source Quench',
    6: 'Alternate Host Address',
    7: 'Reserved',
    8: 'Echo Request',
    9: 'Router Advertisement',
    10: 'Router Solicitation',
    13: 'Timestamp',
    14: 'Timestamp reply',
    19: 'Reserved for security',
} as const

const codeMessage: Record<number, Record<number | 'default', string>> = {
    3: { // Destination Unreachable
        0: 'Destination Network Unreachable',
        1: 'Destination Host Unreachable',
        2: 'Destination Protocol Unreachable',
        3: 'Destination Port Unreachable',
        4: 'Fragmentation required, and DF flag set',
        5: 'Source route failed',
        6: 'Destination network unknown',
        7: 'Destination host unknown',
        8: 'Source host isolated',
        9: 'Network administratively prohibited',
        10: 'Host administratively prohibited',
        11: 'Network unreachable for TOS',
        12: 'Host unreachable for TOS',
        13: 'Communication administratively prohibited',
        14: 'Host Precedence Violation',
        15: 'Precedence cutoff in effect',
        default: 'Destination Unreachable',
    },
    5: { // Redirect Message
        0: 'Redirect Network',
        1: 'Redirect Host',
        2: 'Redirect TOS and Network',
        3: 'Redirect TOS and Host',
        default: 'Redirect',
    },
    11: { // Time Exceeded
        0: 'TTL expired in transit',
        1: 'Fragment reassembly time exceeded',
        default: 'Time Exceeded',
    },
    12: { // Parameter Problem: Bad IP header
        0: 'Pointer indicates the error',
        1: 'Missing a required option',
        2: 'Bad length',
        default: 'Bad IP Header',
    },
}

export class ICMP {
    decoderName = 'icmp'

    emitter?: EventEmitter
    type: number = 0
    code: number = 0
    checksum: number = 0

    constructor(emitter?: EventEmitter) {
        this.emitter = emitter
    }

    // http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    decode(rawPacket: Buffer, offset: number) {
        this.type = rawPacket[offset++]
        this.code = rawPacket[offset++]
        this.checksum = rawPacket.readUInt16BE(offset)

        if (this.emitter)
            this.emitter.emit(this.decoderName, this)

        return this
    }

    toString() {
        let ret = ''

        if (this.type in typeMessage)
            ret = typeMessage[this.type]

        if (this.type in codeMessage) {
            if (this.code in codeMessage[this.type])
                ret += codeMessage[this.type][this.code]
            else
                ret += `${codeMessage[this.type].default} (unknown code ${this.code})`
        }

        if (ret === '')
            ret = `type ${this.type} code ${this.code}`

        return ret
    }
}
