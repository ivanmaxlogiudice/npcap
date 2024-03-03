import { PROTOCOL_ARP, PROTOCOL_IPV4, PROTOCOL_IPV6, ProtocolName } from '@/types'
import { Arp, IPv4, IPv6 } from '../protocols'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

const SNAP = 0xaa
const LSAP = 0x00

export class LLCPacket {
    static decoderName = 'llc-packet'

    /**
     * Destination Service Access Point (DSAP).
     */
    dsap: number

    /**
     * Source Service Access Point (SSAP).
     */
    ssap: number

    /**
     * Control Field.
     *
     * @see {@link https://en.wikipedia.org/wiki/IEEE_802.2#Control_Field | Control Field}
     */
    control: number

    /**
     * Determine which protocol is encapsulated in the payload.
     *
     * @see {@link http://en.wikipedia.org/wiki/EtherType | EtherType}
     */
    type: number

    /**
     * The payload of the packet frame.
     *
     * Supported protocols: IPv4, Arp, IPv6.
     */
    payload: IPv4 | Arp | IPv6

    // https://en.wikipedia.org/wiki/IEEE_802.2#LSAP_Values
    constructor(rawPacket: Buffer, offset: number = 0, emitter?: EventEmitter) {
        this.dsap = rawPacket[offset++]
        this.ssap = rawPacket[offset++]

        if ((this.dsap === SNAP && this.ssap === SNAP) || (this.dsap === LSAP && this.ssap === LSAP)) {
            this.control = rawPacket[offset++]

            offset += 3 // OUI?? Skip 24 bits

            this.type = rawPacket.readUInt16BE(offset)
            offset += 2

            if (this.type < 1536) {
                // this packet is actually some 802.3 type without an ethertype
                throw new Error(`802.3 type without an ethertype ${this.type}.`)
            }
            else {
                // http://en.wikipedia.org/wiki/EtherType
                switch (this.type) {
                    case PROTOCOL_IPV4:
                        this.payload = new IPv4(rawPacket, offset, emitter)
                        break
                    case PROTOCOL_ARP:
                        this.payload = new Arp(rawPacket, offset, emitter)
                        break
                    case PROTOCOL_IPV6:
                        this.payload = new IPv6(rawPacket, offset, emitter)
                        break
                    default:
                        throw new Error(`NpcapPacket: LLCPacket() - Dont know how to decode type ${this.type}.`)
                }
            }
        }
        else {
            throw new Error(`NpcapPacket: LLCPacket() - Unknown LLC types: DSAP: ${this.dsap}, SSAP: ${this.ssap}.`)
        }

        if (emitter)
            emitter.emit(LLCPacket.decoderName, this)
    }

    isIPv4(): this is LLCPacket & { payload: IPv4 } {
        return this.type === PROTOCOL_IPV4
    }

    isArp(): this is LLCPacket & { payload: Arp } {
        return this.type === PROTOCOL_ARP
    }

    isIPv6(): this is LLCPacket & { payload: IPv6 } {
        return this.type === PROTOCOL_IPV6
    }

    toString() {
        let ret = `dsap: ${this.dsap} ssap: ${this.ssap}`

        if (this.type && this.type in ProtocolName)
            ret += ` ${ProtocolName[this.type]} ${this.payload}`
        else
            ret += ` type ${this.type}`

        return ret
    }
}
