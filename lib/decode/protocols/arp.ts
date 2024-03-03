import { EthernetAddr } from '../packets/ethernet'
import { IPv4Addr } from './ipv4'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class Arp {
    static decoderName = 'arp'

    /**
     * Hardware Type.
     *
     * This field specifies the network link protocol type.
     *
     * Example: Ethernet is 1.
     */
    htype: number

    /**
     * Protocol type.
     *
     * Specifies the protocol for which the request
     * is intended.
     *
     * @see {@link https://en.wikipedia.org/wiki/EtherType | EtherType}
     */
    ptype: number

    /**
     * Length of the hardware address.
     */
    hlen: number

    /**
     * Protocol length.
     */
    plen: number

    /**
     * Specifies the operation that the sender is performing:
     *
     * - 1 for request
     * - 2 for reply.
     */
    operation: number

    /**
     * Sender hardware address.
     *
     * Indicate the address of the host sending the request.
     */
    sha: EthernetAddr

    /**
     * Sender protocol address.
     */
    spa: IPv4Addr

    /**
     * Target hardware address.
     *
     * In an ARP request this field is ignored.
     *
     * In an ARP reply this field is used to indicate the
     * address of the host that originated the ARP request.
     */
    tha: EthernetAddr

    /**
     * Target protocol address.
     */
    tpa: IPv4Addr

    // http://en.wikipedia.org/wiki/Address_Resolution_Protocol
    constructor(rawPacket: Buffer, offset: number = 0, emitter?: EventEmitter) {
        this.htype = rawPacket.readUInt16BE(offset)
        this.ptype = rawPacket.readUInt16BE(offset + 2)
        this.hlen = rawPacket[offset + 4]
        this.plen = rawPacket[offset + 5]
        this.operation = rawPacket.readUInt16BE(offset + 6) // 6, 7

        // TODO: This only work for Ethernet + IPv4, if needed need to rework this.
        if (this.hlen === 6 && this.plen === 4) { // Ethernet + IPv4
            this.sha = new EthernetAddr(rawPacket, offset + 8) // 8, 9, 10, 11, 12, 13
            this.spa = new IPv4Addr(rawPacket, offset + 14) // 14, 15, 16, 17
            this.tha = new EthernetAddr(rawPacket, offset + 18) // 18, 19, 20, 21, 22, 23
            this.tpa = new IPv4Addr(rawPacket, offset + 24) // 24, 25, 26, 27
        }
        else {
            throw new Error(`Dont know how to decode other ARP Packets.`)
        }

        if (emitter)
            emitter.emit(Arp.decoderName, this)
    }

    toString() {
        let ret = ''

        if (this.operation === 1)
            ret += 'request'
        else if (this.operation === 2)
            ret += 'reply'
        else
            ret += 'unknown'

        if (this.sha && this.spa)
            ret += ` sender ${this.sha} ${this.spa} target ${this.tha} ${this.tpa}`

        return ret
    }
}
