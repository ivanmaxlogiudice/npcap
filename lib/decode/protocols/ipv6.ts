import type { ProtocolsType } from '../ip-protocols'
import { protocols } from '../ip-protocols'
import { int8_to_hex as hex } from '../utils'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class IPv6Addr {
    addr: number[] = Array.from({ length: 16 })

    decode(rawPacket: Buffer, offset: number = 0) {
        this.addr[0] = rawPacket[offset + 0]
        this.addr[1] = rawPacket[offset + 1]
        this.addr[2] = rawPacket[offset + 2]
        this.addr[3] = rawPacket[offset + 3]
        this.addr[4] = rawPacket[offset + 4]
        this.addr[5] = rawPacket[offset + 5]
        this.addr[6] = rawPacket[offset + 6]
        this.addr[7] = rawPacket[offset + 7]
        this.addr[8] = rawPacket[offset + 8]
        this.addr[9] = rawPacket[offset + 9]
        this.addr[10] = rawPacket[offset + 10]
        this.addr[11] = rawPacket[offset + 11]
        this.addr[12] = rawPacket[offset + 12]
        this.addr[13] = rawPacket[offset + 13]
        this.addr[14] = rawPacket[offset + 14]
        this.addr[15] = rawPacket[offset + 15]

        return this
    }

    toString() {
        return `${hex[this.addr[0]] + hex[this.addr[1]]}:${hex[this.addr[2]]}${hex[this.addr[3]]}:${
           hex[this.addr[4]]}${hex[this.addr[5]]}:${hex[this.addr[6]]}${hex[this.addr[7]]}:${
           hex[this.addr[8]]}${hex[this.addr[9]]}:${hex[this.addr[10]]}${hex[this.addr[11]]}:${
           hex[this.addr[12]]}${hex[this.addr[13]]}:${hex[this.addr[14]]}${hex[this.addr[15]]}`
    }
}

export class IPv6 {
    static decoderName = 'ipv6'

    version!: number
    trafficClass!: number
    flowLabel!: number
    payloadLength!: number
    nextHeader!: number
    hopLimit!: number
    saddr!: IPv6Addr
    daddr!: IPv6Addr
    payload?: ProtocolsType
    protocolName?: string

    constructor(
        public emitter?: EventEmitter,
    ) { }

    // http://en.wikipedia.org/wiki/IPv6
    decode(rawPacket: Buffer, offset: number = 0) {
        const originalOffset = offset

        this.version = ((rawPacket[offset] & 0xf0) >> 4) // first 4 bits
        this.trafficClass = ((rawPacket[offset] & 0x0f) << 4) | ((rawPacket[offset + 1] & 0xf0) >> 4)
        this.flowLabel = ((rawPacket[offset + 1] & 0x0f) << 16) + (rawPacket[offset + 2] << 8) + rawPacket[offset + 3]

        this.payloadLength = rawPacket.readUInt16BE(offset + 4)

        this.nextHeader = rawPacket[offset + 6]
        this.hopLimit = rawPacket[offset + 7]

        this.saddr = new IPv6Addr().decode(rawPacket, offset + 8)
        this.daddr = new IPv6Addr().decode(rawPacket, offset + 24)

        offset = originalOffset + 40

        // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        this.payload = protocols(this.nextHeader, this.emitter, rawPacket, offset, rawPacket.length - 40)
        if (this.payload === undefined)
            this.protocolName = 'Unknown'

        if (this.emitter)
            this.emitter.emit(IPv6.decoderName, this)

        return this
    }

    toString() {
        let ret = `${this.saddr} -> ${this.daddr} `

        if (this.payload === undefined)
            ret += `proto ${this.nextHeader}`
        else
            ret += this.payload.constructor.name

        return `${ret} ${this.payload}`
    }
}
