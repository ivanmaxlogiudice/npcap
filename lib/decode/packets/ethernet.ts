import { int8_to_hex as hex } from '@/decode/utils'
import { PROTOCOL_ARP, PROTOCOL_IPV4, PROTOCOL_IPV6, PROTOCOL_VLAN, ProtocolName } from '@/types'
import { Arp, IPv4, IPv6, Vlan } from '../protocols'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class EthernetAddr {
    addr: number[] = Array.from({ length: 4 })

    constructor(rawPacket: Buffer, offset: number = 0) {
        this.addr[0] = rawPacket[offset]
        this.addr[1] = rawPacket[offset + 1]
        this.addr[2] = rawPacket[offset + 2]
        this.addr[3] = rawPacket[offset + 3]
        this.addr[4] = rawPacket[offset + 4]
        this.addr[5] = rawPacket[offset + 5]

        return this
    }

    toString() {
        return `${hex[this.addr[0]]}:${hex[this.addr[1]]}:${hex[this.addr[2]]}:${hex[this.addr[3]]}:${hex[this.addr[4]]}:${hex[this.addr[5]]}`
    }
}

export class EthernetPacket {
    static decoderName = 'ethernet-packet'

    /**
     * Destination Address
     */
    dhost?: EthernetAddr

    /**
     * Source Address
     */
    shost?: EthernetAddr

    /**
     * Determine which protocol is encapsulated in the payload.
     *
     * @see {@link http://en.wikipedia.org/wiki/EtherType | EtherType}
     */
    type?: number

    /**
     * VLAN-tagged (802.1Q)
     *
     * @see {@link https://en.wikipedia.org/wiki/IEEE_802.1Q | IEEE 802.1Q}
     */
    vlan?: Vlan

    /**
     * The payload of the packet frame.
     *
     * Supported protocols: IPv4, Arp, IPv6.
     */
    payload?: IPv4 | Arp | IPv6

    constructor(
        public emitter?: EventEmitter,
    ) { }

    // https://en.wikipedia.org/wiki/Ethernet_frame
    decode(rawPacket: Buffer, offset: number = 0) {
        this.dhost = new EthernetAddr(rawPacket, offset)
        offset += 6

        this.shost = new EthernetAddr(rawPacket, offset)
        offset += 6

        this.type = rawPacket.readUInt16BE(offset)
        offset += 2

        // VLAN-tagged (802.1Q)
        if (this.type === PROTOCOL_VLAN) {
            this.vlan = new Vlan(this.emitter).decode(rawPacket, offset)
            offset += 2

            this.type = rawPacket.readUInt16BE(offset)
            offset += 2
        }

        if (this.type < 1536) {
            // this packet is actually some 802.3 type without an ethertype
            this.type = 0
        }
        else {
            switch (this.type) {
                case PROTOCOL_IPV4:
                    this.payload = new IPv4(this.emitter).decode(rawPacket, offset)
                    break
                case PROTOCOL_ARP:
                    this.payload = new Arp(this.emitter).decode(rawPacket, offset)
                    break
                case PROTOCOL_IPV6:
                    this.payload = new IPv6(this.emitter).decode(rawPacket, offset)
                    break
                default:
                    this.payload = undefined
                    console.log(`NpcapPacket: EthernetPacket() - Dont know how to decode ethertype ${this.type}.`)
            }
        }

        if (this.emitter)
            this.emitter.emit(EthernetPacket.decoderName, this)

        return this
    }

    isIPv4(): this is EthernetPacket & { payload: IPv4 } {
        return this.type === PROTOCOL_IPV4
    }

    isArp(): this is EthernetPacket & { payload: Arp } {
        return this.type === PROTOCOL_ARP
    }

    isIPv6(): this is EthernetPacket & { payload: IPv6 } {
        return this.type === PROTOCOL_IPV6
    }

    toString() {
        let ret = `${this.shost} -> ${this.dhost}`

        if (this.vlan)
            ret += ` vlan ${this.vlan}`

        if (this.type && this.type in ProtocolName)
            ret += ` ${ProtocolName[this.type]}`
        else
            ret += ` ethertype ${this.type}`

        return `${ret} ${this.payload}`
    }
}
