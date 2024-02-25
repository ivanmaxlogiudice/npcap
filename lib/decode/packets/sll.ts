import { ETHERNET_TYPE_ARP, ETHERNET_TYPE_IPV4, ETHERNET_TYPE_IPV6, EthernetTypeString } from '../../types'
import { Arp } from '../protocols/arp'
import { IPv4 } from '../protocols/ipv4'
import { IPv6 } from '../protocols/ipv6'
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

    packetType!: number
    addressType!: number
    addressLen!: number
    address!: SLLAddr
    ethertype!: number
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

        this.ethertype = rawPacket.readUInt16BE(offset)
        offset += 2

        if (this.ethertype < 1536) {
            // this packet is actually some 802.3 type without an ethertype
            this.ethertype = 0
        }
        else {
            // http://en.wikipedia.org/wiki/EtherType
            switch (this.ethertype) {
                case ETHERNET_TYPE_IPV4:
                    this.payload = new IPv4(this.emitter).decode(rawPacket, offset)
                    break
                case ETHERNET_TYPE_ARP:
                    this.payload = new Arp(this.emitter).decode(rawPacket, offset)
                    break
                case ETHERNET_TYPE_IPV6:
                    this.payload = new IPv6(this.emitter).decode(rawPacket, offset)
                    break
                default:
                    this.payload = undefined
                    console.log(`NpcapPacket: SLLPacket() - Dont know how to decode ethertype ${this.ethertype}.`)
            }
        }

        return this
    }

    toString() {
        let ret = ['recv_us', 'broadcast', 'multicast', 'remote_remote', 'sent_us'][this.packetType] ?? ''

        ret += ` addrtype ${this.addressType} ${this.address}`

        if (this.ethertype in EthernetTypeString)
            ret += ` ${EthernetTypeString[this.ethertype]}`
        else
            ret += ` ethertype ${this.ethertype}`

        return `${ret} ${this.payload}`
    }
}
