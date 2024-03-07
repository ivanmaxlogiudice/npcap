import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class Vlan {
    static decoderName = 'vlan'

    priority: number
    canonicalFormat: number
    id: number

    // http://en.wikipedia.org/wiki/IEEE_802.1Q
    constructor(rawPacket: Buffer, offset: number = 0, emitter?: EventEmitter) {
        this.priority = (rawPacket[offset] & 0xE0) >> 5
        this.canonicalFormat = (rawPacket[offset] & 0x10) >> 4
        this.id = ((rawPacket[offset] & 0x0F) << 8) | rawPacket[offset + 1]

        if (emitter)
            emitter.emit(Vlan.decoderName, this)
    }

    toString() {
        return `${this.priority} ${this.canonicalFormat} ${this.id}`
    }
}
