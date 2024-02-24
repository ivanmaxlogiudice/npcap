import { ETHERNET_TYPE_ARP, ETHERNET_TYPE_IPV4, ETHERNET_TYPE_IPV6, ETHERNET_TYPE_VLAN } from '../../types'
import { Arp } from '../protocols/arp'
import { IPv4 } from '../protocols/ipv4'
import { IPv6 } from '../protocols/ipv6'
import { Vlan } from '../protocols/vlan'
import { int8_to_hex as hex } from '../utils'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

const typeMessage: Record<number, string> = {
    [ETHERNET_TYPE_IPV4]: 'IPv4',
    [ETHERNET_TYPE_ARP]: 'Arp',
    [ETHERNET_TYPE_IPV6]: 'IPv6',
}

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
    emitter?: EventEmitter
    dhost?: EthernetAddr
    shost?: EthernetAddr
    ethertype: number = 0
    vlan?: Vlan
    payload?: IPv4 | Arp | IPv6

    constructor(emitter?: EventEmitter) {
        this.emitter = emitter
    }

    decode(rawPacket: Buffer, offset: number = 0): EthernetPacket {
        this.dhost = new EthernetAddr(rawPacket, offset)
        offset += 6

        this.shost = new EthernetAddr(rawPacket, offset)
        offset += 6

        this.ethertype = rawPacket.readUInt16BE(offset)
        offset += 2

        // VLAN-tagged (802.1Q)
        if (this.ethertype === ETHERNET_TYPE_VLAN) {
            this.vlan = new Vlan().decode(rawPacket, offset)
            offset += 2

            this.ethertype = rawPacket.readUInt16BE(offset)
            offset += 2
        }

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
                    console.log(`NpcapPacket: EthernetPacket() - Dont know how to decode ethertype ${this.ethertype}.`)
            }
        }

        return this
    }

    toString() {
        let ret = `${this.shost} -> ${this.dhost}`

        if (this.vlan)
            ret += ` vlan ${this.vlan}`

        if (this.ethertype in typeMessage)
            ret += ` ${typeMessage[this.ethertype]}`
        else
            ret += ` ethertype ${this.ethertype}`

        return `${ret} ${this.payload}`
    }
}
