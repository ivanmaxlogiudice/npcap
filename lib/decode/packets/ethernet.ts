import { ETHERNET_TYPE_IPV4, ETHERNET_TYPE_VLAN } from '../../types'
import { IPv4 } from '../protocols/ipv4'
import { int8_to_hex as hex } from '../utils'
import { Vlan } from '../vlan'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class EthernetAddr {
    addr: number[] = Array.from({ length: 4 })

    constructor(rawPacket: Buffer, offset: number) {
        this.addr[0] = rawPacket[offset]
        this.addr[1] = rawPacket[offset + 1]
        this.addr[2] = rawPacket[offset + 2]
        this.addr[3] = rawPacket[offset + 3]
        this.addr[4] = rawPacket[offset + 4]
        this.addr[5] = rawPacket[offset + 5]
    }

    toString() {
        return `${hex[this.addr[0]]}:${hex[this.addr[1]]}:${hex[this.addr[2]]}:${hex[this.addr[3]]}:${hex[this.addr[4]]}:${hex[this.addr[5]]}:`
    }
}

export class EthernetPacket {
    emitter?: EventEmitter
    dhost?: EthernetAddr
    shost?: EthernetAddr
    ethertype: number = 0
    vlan?: Vlan
    payload?: IPv4

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

        switch (this.ethertype) {
            case 0x800:
                ret += ' IPv4'
                break
            default:
                ret += ` ethertype ${this.ethertype}`
        }

        return `${ret} ${this.payload}`
    }
}