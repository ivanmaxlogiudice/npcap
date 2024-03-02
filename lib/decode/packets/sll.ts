import { PROTOCOL_ARP, PROTOCOL_IPV4, PROTOCOL_IPV6, ProtocolName } from '@/types'
import { Arp, IPv4, IPv6 } from '../protocols'
import { int8_to_hex } from '../utils'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class SLLAddr {
    addr!: Array<number>

    decode(rawPacket: Buffer, offset: number, len: number) {
        this.addr = Array.from({ length: len })

        for (let i = 0; i < len; i++)
            this.addr[i] = rawPacket[offset + i]

        return this
    }

    toString() {
        let ret = ''
        let i
        console.log(this.addr.length)
        for (i = 0; i < this.addr.length - 1; i++)
            ret += `${int8_to_hex[this.addr[i]]}:`

        ret += int8_to_hex[this.addr[i + 1]]

        return ret
    }
}

export class SLLPacket {
    static decoderName = 'sll-packet'

    /**
     * Packet type field.
     *
     * @see {@link https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html | Linux SLL}
     */
    packetType?: number

    /**
     * Address type.
     *
     * @see {@link https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html | Linux SLL}
     */
    addressType?: number

    /**
     * Address length
     *
     * @see {@link https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html | Linux SLL}
     */
    addressLen?: number

    /**
     * Source address.
     *
     * @see {@link https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html | Linux SLL}
     */
    address?: SLLAddr

    /**
     * Determine which protocol is encapsulated in the payload.
     *
     * @see {@link http://en.wikipedia.org/wiki/EtherType | EtherType}
     */
    type?: number

    /**
     * The payload of the packet frame.
     *
     * Supported protocols: IPv4, Arp, IPv6.
     */
    payload?: IPv4 | Arp | IPv6

    constructor(
        public emitter?: EventEmitter,
    ) {}

    // https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
    decode(rawPacket: Buffer, offset: number = 0) {
        this.packetType = rawPacket.readUInt16BE(offset)
        offset += 2

        this.addressType = rawPacket.readUInt16BE(offset)
        offset += 2

        this.addressLen = rawPacket.readUInt16BE(offset)
        offset += 2

        this.address = new SLLAddr().decode(rawPacket, offset, this.addressLen)
        offset += 8 // address uses 8 bytes in frame, but only address_len bytes are significant

        this.type = rawPacket.readUInt16BE(offset)
        offset += 2

        if (this.type < 1536) {
            // this packet is actually some 802.3 type without an ethertype
            this.type = 0
        }
        else {
            // http://en.wikipedia.org/wiki/EtherType
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
                    console.log(`NpcapPacket: SLLPacket() - Dont know how to decode ethertype ${this.type}.`)
            }
        }

        if (this.emitter)
            this.emitter.emit(SLLPacket.decoderName, this)

        return this
    }

    isIPv4(): this is SLLPacket & { payload: IPv4 } {
        return this.type === PROTOCOL_IPV4
    }

    isArp(): this is SLLPacket & { payload: Arp } {
        return this.type === PROTOCOL_ARP
    }

    isIPv6(): this is SLLPacket & { payload: IPv6 } {
        return this.type === PROTOCOL_IPV6
    }

    toString() {
        let ret = ''

        if (this.packetType)
            ret = ['recv_us', 'broadcast', 'multicast', 'remote_remote', 'sent_us'][this.packetType] ?? ''

        ret += ` addrtype ${this.addressType} ${this.address}`

        if (this.type && this.type in ProtocolName)
            ret += ` ${ProtocolName[this.type]}`
        else
            ret += ` ethertype ${this.type}`

        return `${ret} ${this.payload}`
    }
}
