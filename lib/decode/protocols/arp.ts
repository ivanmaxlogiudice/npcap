import { EthernetAddr } from '../packets/ethernet'
import { IPv4Addr } from './ipv4'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class Arp {
    static decoderName = 'arp'
    htype!: number
    ptype!: number
    hlen!: number
    plen!: number
    operation!: number

    sender_ha!: EthernetAddr
    sender_pa!: IPv4Addr
    target_ha!: EthernetAddr
    target_pa!: IPv4Addr

    constructor(
        public emitter?: EventEmitter,
    ) {}

    // http://en.wikipedia.org/wiki/Address_Resolution_Protocol
    decode(rawPacket: Buffer, offset: number = 0) {
        this.htype = rawPacket.readUInt16BE(offset)
        this.ptype = rawPacket.readUInt16BE(offset + 2)
        this.hlen = rawPacket[offset + 4]
        this.plen = rawPacket[offset + 5]
        this.operation = rawPacket.readUInt16BE(offset + 6) // 6, 7

        if (this.hlen === 6 && this.plen === 4) { // ethernet + IPv4
            this.sender_ha = new EthernetAddr(rawPacket, offset + 8) // 8, 9, 10, 11, 12, 13
            this.sender_pa = new IPv4Addr().decode(rawPacket, offset + 14) // 14, 15, 16, 17
            this.target_ha = new EthernetAddr(rawPacket, offset + 18) // 18, 19, 20, 21, 22, 23
            this.target_pa = new IPv4Addr().decode(rawPacket, offset + 24) // 24, 25, 26, 27
        }

        if (this.emitter)
            this.emitter.emit(Arp.decoderName, this)

        return this
    }

    toString() {
        let ret = ''

        if (this.operation === 1)
            ret += 'request'
        else if (this.operation === 2)
            ret += 'reply'
        else
            ret += 'unknown'

        if (this.sender_ha && this.sender_pa)
            ret += ` sender ${this.sender_ha} ${this.sender_pa} target ${this.target_ha} ${this.target_pa}`

        return ret
    }
}
