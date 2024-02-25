import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class Vlan {
    static decoderName = 'vlan'

    priority: number = 0
    canonicalFormat: number = 0
    id: number = 0

    constructor(
        public emitter?: EventEmitter,
    ) {}

    // http://en.wikipedia.org/wiki/IEEE_802.1Q
    decode(rawPacket: Buffer, offset: number = 0) {
        this.priority = (rawPacket[offset] & 0xE0) >> 5
        this.canonicalFormat = (rawPacket[offset] & 0x10) >> 4
        this.id = ((rawPacket[offset] & 0x0F) << 8) | rawPacket[offset + 1]

        if (this.emitter)
            this.emitter.emit(Vlan.decoderName, this)

        return this
    }

    toString() {
        return `${this.priority} ${this.canonicalFormat} ${this.id}`
    }
}
