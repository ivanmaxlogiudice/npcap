import { ETHERNET_TYPE_ARP, ETHERNET_TYPE_IPV4, ETHERNET_TYPE_IPV6, EthernetTypeString } from '../../types'
import { Arp } from '../protocols/arp'
import { IPv4 } from '../protocols/ipv4'
import { IPv6 } from '../protocols/ipv6'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

const SNAP = 0xaa
const LSAP = 0x00

export class LLCPacket {
    static decoderName = 'llc-packet'

    dsap!: number
    ssap!: number

    control?: number
    type?: number
    payload?: IPv4 | Arp | IPv6

    constructor(
        public emitter?: EventEmitter,
    ) {}

    // https://en.wikipedia.org/wiki/IEEE_802.2#LSAP_Values
    decode(rawPacket: Buffer, offset: number = 0) {
        this.dsap = rawPacket[offset++]
        this.ssap = rawPacket[offset++]

        if ((this.dsap === SNAP && this.ssap === SNAP) || (this.dsap === LSAP && this.ssap === LSAP)) {
            this.control = rawPacket[offset++]

            offset += 3 // OUI?? Skip 24 bits

            this.type = rawPacket.readUInt16BE(offset)
            offset += 2

            if (this.type < 1536) {
                console.log(`NpcapPacket: LLCPacket() - 802.3 type without type ${this.type}.`)
                console.log(this)

                // this packet is actually some 802.3 type without an ethertype
                this.type = 0
            }
            else {
                // http://en.wikipedia.org/wiki/EtherType
                switch (this.type) {
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
                        console.log(`NpcapPacket: EthernetPacket() - Dont know how to decode ethertype ${this.type}.`)
                }
            }
        }
        else {
            console.log(`NpcapPacket: EthernetPacket() - Unknown LLC types: DSAP: ${this.dsap}, SSAP: ${this.ssap}.`)
        }

        if (this.emitter)
            this.emitter.emit(LLCPacket.decoderName, this)

        return this
    }

    toString() {
        let ret = `dsap: ${this.dsap} ssap: ${this.ssap}`

        if (this.type && this.type in EthernetTypeString)
            ret += ` ${EthernetTypeString[this.type]} ${this.payload}`
        else
            ret += ` type ${this.type}`

        return ret
    }
}
