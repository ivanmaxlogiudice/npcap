import type { ProtocolsType } from '../ip-protocols'
import { HeaderExtension, ICMP, IGMP, IPv4, NoNext, Tcp, Udp } from '.'
import { protocols } from '../ip-protocols'
import { int8_to_hex as hex } from '../utils'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class IPv6Addr {
    addr = Array.from<number>({ length: 16 })

    constructor(rawPacket: Buffer, offset: number = 0) {
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

    /**
     * IP Version.
     */
    version: number

    /**
     * Traffic Class.
     *
     * Determine class or priority of IPv6 packet.
     */
    trafficClass: number

    /**
     * Flow Label.
     *
     * Used by a source to label the packets belonging to the same flow in order to request special
     * handling by intermediate IPv6 routers, such as non-default quality of service or real-time service.
     */
    flowLabel: number

    /**
     * Payload Length.
     *
     * Indicates the total size of the payload which tells routers about
     * the amount of information a particular packet contains in its payload.
     */
    payloadLength: number

    /**
     * Next Header.
     *
     * Indicates the type of extension header(if present)
     * immediately following the IPv6 header.
     */
    nextHeader: number

    /**
     * Hop Limit.
     *
     * Indicates the maximum number of intermediate nodes IPv6 packet is allowed to travel.
     *
     * Its value gets decremented by one, by each node that forwards
     * the packet and the packet is discarded if the value decrements to 0.
     */
    hopLimit: number

    /**
     * Source Address.
     *
     * The IPv6 address of the original source of the packet.
     */
    saddr: IPv6Addr

    /**
     * Destination Address.
     *
     * The IPv6 address of the final destination(in most cases).
     */
    daddr: IPv6Addr

    /**
     * The payload of the packet frame.
     */
    payload: ProtocolsType

    // https://www.geeksforgeeks.org/internet-protocol-version-6-ipv6-header/
    constructor(rawPacket: Buffer, offset: number = 0, emitter?: EventEmitter) {
        const originalOffset = offset

        this.version = ((rawPacket[offset] & 0xf0) >> 4) // first 4 bits
        this.trafficClass = ((rawPacket[offset] & 0x0f) << 4) | ((rawPacket[offset + 1] & 0xf0) >> 4)
        this.flowLabel = ((rawPacket[offset + 1] & 0x0f) << 16) + (rawPacket[offset + 2] << 8) + rawPacket[offset + 3]

        this.payloadLength = rawPacket.readUInt16BE(offset + 4)

        this.nextHeader = rawPacket[offset + 6]
        this.hopLimit = rawPacket[offset + 7]

        this.saddr = new IPv6Addr(rawPacket, offset + 8)
        this.daddr = new IPv6Addr(rawPacket, offset + 24)

        offset = originalOffset + 40

        // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        this.payload = protocols(this.nextHeader, emitter, rawPacket, offset, rawPacket.length - 40)

        if (emitter)
            emitter.emit(IPv6.decoderName, this)

        return this
    }

    isHeaderExtension(): this is { payload: HeaderExtension } {
        return this.payload instanceof HeaderExtension
    }

    isICMP(): this is { payload: ICMP } {
        return this.payload instanceof ICMP
    }

    isIGMP(): this is { payload: IGMP } {
        return this.payload instanceof IGMP
    }

    isIPv4(): this is { payload: IPv4 } {
        return this.payload instanceof IPv4
    }

    isTcp(): this is { payload: Tcp } {
        return this.payload instanceof Tcp
    }

    isUdp(): this is { payload: Udp } {
        return this.payload instanceof Udp
    }

    isIPv6(): this is { payload: IPv6 } {
        return this.payload instanceof IPv6
    }

    isNoNext(): this is { payload: NoNext } {
        return this.payload instanceof NoNext
    }

    toString() {
        return `${this.saddr} -> ${this.daddr} ${this.payload.constructor.name} ${this.payload}`
    }
}
