import { protocols } from '../protocols'
import { int8_to_dec } from '../utils'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class IPFlags {
    emitter?: EventEmitter
    reserved?: boolean
    doNotFragment?: boolean
    moreFragments?: boolean

    constructor(emitter?: EventEmitter) {
        this.emitter = emitter
    }

    decode(rawFlags: number): IPFlags {
        this.reserved = Boolean((rawFlags & 0x80) >> 7)
        this.doNotFragment = Boolean((rawFlags & 0x40) > 0)
        this.moreFragments = Boolean((rawFlags & 0x20) > 0)

        return this
    }

    toString() {
        let ret: string = '['
        if (this.reserved)
            ret += 'r'
        if (this.doNotFragment)
            ret += 'd'
        if (this.moreFragments)
            ret += 'm'
        ret += ']'

        return ret
    }
}

export class IPv4Addr {
    static decoderName = 'ipv4-addr'

    emitter?: EventEmitter
    addr: number[] = Array.from({ length: 4 })

    constructor(emitter?: EventEmitter) {
        this.emitter = emitter
    }

    decode(rawPacket: Buffer, offset: number = 0) {
        this.addr[0] = rawPacket[offset]
        this.addr[1] = rawPacket[offset + 1]
        this.addr[2] = rawPacket[offset + 2]
        this.addr[3] = rawPacket[offset + 3]

        if (this.emitter)
            this.emitter.emit(IPv4Addr.decoderName, this)

        return this
    }

    toString() {
        return `${int8_to_dec[this.addr[0]]}.${int8_to_dec[this.addr[1]]}.${int8_to_dec[this.addr[2]]}.${int8_to_dec[this.addr[3]]}`
    }
}

export class IPv4 {
    static decoderName = 'ipv4'

    version: number = 0
    headerLength: number = 0
    diffserv: number = 0
    length: number = 0
    identification: number = 0
    flags?: IPFlags
    fragmentOffset: number = 0
    ttl: number = 0
    protocol: number = 0
    headerChecksum: number = 0
    saddr?: IPv4Addr
    daddr?: IPv4Addr
    protocolName?: string
    payload?: any

    constructor(
        public emitter?: EventEmitter,
    ) { }

    // http://en.wikipedia.org/wiki/IPv4
    decode(rawPacket: Buffer, offset: number = 0) {
        const originalOffset = offset

        this.version = (rawPacket[offset] & 0xf0) >> 4
        this.headerLength = (rawPacket[offset] & 0x0f) << 2
        offset += 1

        this.diffserv = rawPacket[offset]
        offset += 1

        this.length = rawPacket.readUInt16BE(offset)
        offset += 2

        this.identification = rawPacket.readUInt16BE(offset)
        offset += 2

        this.flags = new IPFlags(this.emitter).decode(rawPacket[offset])
        // flags only uses the top 3 bits of offset so don't advance yet
        this.fragmentOffset = ((rawPacket.readUInt16BE(offset) & 0x1fff) << 3) // 13-bits from 6, 7
        offset += 2

        this.ttl = rawPacket[offset]
        offset += 1

        this.protocol = rawPacket[offset]
        offset += 1

        this.headerChecksum = rawPacket.readUInt16BE(offset)
        offset += 2

        this.saddr = new IPv4Addr(this.emitter).decode(rawPacket, offset)
        offset += 4

        this.daddr = new IPv4Addr(this.emitter).decode(rawPacket, offset)
        offset += 4

        // TODO: parse IP "options" if header_length > 5
        offset = originalOffset + this.headerLength

        // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        this.payload = protocols(this.protocol, this.emitter, rawPacket, offset, this.length - this.headerLength)
        if (this.payload === undefined)
            this.protocolName = 'Unknown'

        if (this.emitter)
            this.emitter.emit(IPv4.decoderName, this)

        return this
    }

    toString() {
        let ret = `${this.saddr} -> ${this.daddr} `
        const flags = this.flags?.toString() || ''

        if (flags.length > 2)
            ret += `flags ${flags} `

        if (this.payload === undefined)
            ret += `protocol ${this.protocol}`
        else
            ret += this.payload.constructor.name

        return `${ret} ${this.payload}`
    }
}
