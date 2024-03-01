import { IPv4, IPv6 } from '../protocols'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class NullPacket {
    static decoderName = 'null-packet'

    /**
     * Determine which protocol is encapsulated in the payload.
     *
     * @see {@link https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html | LINKTYPE_NULL}
     */
    type?: number

    /**
     * The payload of the packet frame.
     *
     * Supported protocols: IPv4, IPv6.
     */
    payload?: IPv4 | IPv6

    constructor(
        public emitter?: EventEmitter,
    ) {}

    // https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
    decode(rawPacket: Buffer, offset: number = 0) {
        if (rawPacket[offset] === 0 && rawPacket[offset + 1] === 0)
            this.type = rawPacket[offset + 3]
        else
            this.type = rawPacket[offset]

        switch (this.type) {
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
                console.log(`NpcapPacket: NullPacket() - Dont know how to decode protocol family ${this.type}.`)
        }

        if (this.emitter)
            this.emitter.emit(NullPacket.decoderName, this)

        return this
    }

    isIPv4(): this is NullPacket & { payload: IPv4 } {
        return this.type === 2
    }

    isIPv6(): this is NullPacket & { payload: IPv6 } {
        return this.type !== undefined && [24, 28, 30].includes(this.type)
    }

    toString() {
        return `${this.type} ${this.payload}`
    }
}
