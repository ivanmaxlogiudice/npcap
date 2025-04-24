import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'
import { IPv4, IPv6 } from '../protocols'

export class NullPacket {
    static decoderName = 'null-packet'

    /**
     * Determine which protocol is encapsulated in the payload.
     *
     * @see {@link https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html | LINKTYPE_NULL}
     */
    type: number

    /**
     * The payload of the packet frame.
     *
     * Supported protocols: IPv4, IPv6.
     */
    payload: IPv4 | IPv6

    // https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
    constructor(rawPacket: Buffer, offset: number = 0, emitter?: EventEmitter) {
        if (rawPacket[offset] === 0 && rawPacket[offset + 1] === 0)
            this.type = rawPacket[offset + 3]
        else
            this.type = rawPacket[offset]

        switch (this.type) {
            case 2:
                this.payload = new IPv4(rawPacket, offset + 4, emitter)
                break
            case 24:
            case 28:
            case 30:
                this.payload = new IPv6(rawPacket, offset + 4, emitter)
                break
            default:
                throw new Error(`Dont know how to decode protocol family ${this.type}.`)
        }

        if (emitter)
            emitter.emit(NullPacket.decoderName, this)
    }

    isIPv4(): this is { payload: IPv4 } {
        return this.payload instanceof IPv4
    }

    isIPv6(): this is { payload: IPv6 } {
        return this.payload instanceof IPv6
    }

    toString() {
        return `${this.type} ${this.payload}`
    }
}
