import { DNS } from './dns'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class Udp {
    static decoderName = 'udp'

    /**
     * Source port number.
     */
    sport: number

    /**
     * Destination port number.
     */
    dport: number

    /**
     * Length.
     *
     * Specifies the length in bytes of the UDP header and UDP data.
     *
     * The minimum length is 8 bytes, the length of the header.
     */
    length: number

    /**
     * Checksum.
     *
     * Used for error-checking of the header and data.
     */
    checksum: number

    /**
     * Data Buffer.
     */
    data: Buffer

    // https://en.wikipedia.org/wiki/User_Datagram_Protocol
    constructor(rawPacket: Buffer, offset: number = 0, emitter?: EventEmitter) {
        this.sport = rawPacket.readUInt16BE(offset)
        offset += 2

        this.dport = rawPacket.readUInt16BE(offset)
        offset += 2

        this.length = rawPacket.readUInt16BE(offset)
        offset += 2

        this.checksum = rawPacket.readUInt16BE(offset)
        offset += 2

        this.data = rawPacket.subarray(offset, offset + (this.length - 8))

        if (emitter)
            emitter.emit(Udp.decoderName, this)
    }

    toString() {
        let ret = `UDP ${this.sport} -> ${this.dport} len ${this.length}`

        if (this.sport === 53 || this.dport === 53)
            ret += (new DNS(this.data, 0).toString())

        return ret
    }
}
