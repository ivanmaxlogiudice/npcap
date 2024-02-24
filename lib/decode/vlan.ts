import type { Buffer } from 'node:buffer'

export class Vlan {
    priority: number = 0
    canonicalFormat: number = 0
    id: number = 0

    // http://en.wikipedia.org/wiki/IEEE_802.1Q
    decode(rawPacket: Buffer, offset: number) {
        this.priority = (rawPacket[offset] & 0xE0) >> 5
        this.canonicalFormat = (rawPacket[offset] & 0x10) >> 4
        this.id = ((rawPacket[offset] & 0x0F) << 8) | rawPacket[offset + 1]

        return this
    }

    toString() {
        return `${this.priority} ${this.canonicalFormat} ${this.id}`
    }
}
