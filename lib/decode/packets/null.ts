import { IPv4 } from '../protocols/ipv4'
import { IPv6 } from '../protocols/ipv6'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class NullPacket {
    static decoderName = 'null-packet'

    pftype!: number
    payload?: IPv4 | IPv6

    constructor(
        public emitter?: EventEmitter,
    ) {}

    // https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
    decode(rawPacket: Buffer, offset: number = 0) {
        if (rawPacket[offset] === 0 && rawPacket[offset + 1] === 0)
            this.pftype = rawPacket[offset + 3]
        else
            this.pftype = rawPacket[offset]

        switch (this.pftype) {
            case 2:
                this.payload = new IPv4(this.emitter).decode(rawPacket, offset + 4)
                break
            case 24:
            case 28:
            case 30:
                this.payload = new IPv6(this.emitter).decode(rawPacket, offset + 4)
                break
            default:
                this.payload = undefined
                console.log(`NpcapPacket: NullPacket() - Dont know how to decode protocol family ${this.pftype}.`)
        }

        if (this.emitter)
            this.emitter.emit(NullPacket.decoderName, this)

        return this
    }

    toString() {
        return `${this.pftype} ${this.payload}`
    }
}
