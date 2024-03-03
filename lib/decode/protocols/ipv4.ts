import type { ProtocolsType } from '../ip-protocols'
import { protocols } from '../ip-protocols'
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

        if (this.reserved) ret += 'r'
        if (this.doNotFragment) ret += 'd'
        if (this.moreFragments) ret += 'm'

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

    /**
     * IP Version.
     *
     * This is always 4 in IPv4.
     */
    version = 4

    /**
     * Header Length.
     *
     * Contains the size of the IPv4 Header
     */
    headerLength?: number

    /**
     * Differentiated Services Code Point
     *
     * @see {@link https://en.wikipedia.org/wiki/Internet_Protocol_version_4#DSCP | DSCP}
     */
    diffserv?: number

    /**
     * Total Length.
     *
     * Defines the entire packet size in bytes, including header and data.
     *
     * The minimum size is 20 bytes (header without data) and the maximum is 65,535 bytes.
     */
    length?: number

    /**
     * Identification.
     *
     * Used for uniquely identifying the group of fragments of a single IP datagram.
     */
    identification?: number

    /**
     * Flags.
     *
     * Used to control or identify fragments.
     * They are (in order, from most significant to least significant):
     *
     * - bit 0: Reserved; must be zero.
     * - bit 1: Don't Fragment (DF).
     * - bit 2: More Fragments (MF).
     */
    flags?: IPFlags

    /**
     * Fragment offset.
     *
     * Specifies the offset of a particular fragment relative to the beginning of the original unfragmented IP datagram.
     *
     * @see {@link https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Fragment_offset | Fragment Offset}
     */
    fragmentOffset?: number

    /**
     * Time to live.
     *
     * Specified in seconds, but time intervals less than 1 second are rounded up to 1.
     */
    ttl?: number

    /**
     * Protocol.
     *
     * The protocol used in the data portion of the IP datagram.
     */
    protocol?: number

    /**
     * Header checksum.
     *
     * Used for error checking of the header.
     *
     * @see {@link https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Header_checksum | Header Checksum}
     */
    headerChecksum?: number

    /**
     * Source address.
     *
     * The IPv4 address of the sender of the packet.
     */
    saddr?: IPv4Addr

    /**
     * Destination address.
     *
     * The IPv4 address of the receiver of the packet.
     */
    daddr?: IPv4Addr

    /**
     * The payload of the packet frame.
     */
    payload?: ProtocolsType

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

        // TODO: parse IP "options" if headerLength > 5
        offset = originalOffset + this.headerLength

        // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        this.payload = protocols(this.protocol, this.emitter, rawPacket, offset, this.length - this.headerLength)

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
