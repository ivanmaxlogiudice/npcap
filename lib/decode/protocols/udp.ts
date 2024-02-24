import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class Udp {
    decoderName = 'udp'

    emitter?: EventEmitter
    sport: number = 0
    dport: number = 0
    length: number = 0
    checksum: number = 0
    data?: Buffer

    constructor(emitter?: EventEmitter) {
        this.emitter = emitter
    }

    decode(rawPacket: Buffer, offset: number) {
        this.sport = rawPacket.readUInt16BE(offset)
        offset += 2

        this.dport = rawPacket.readUInt16BE(offset)
        offset += 2

        this.length = rawPacket.readUInt16BE(offset)
        offset += 2

        this.checksum = rawPacket.readUInt16BE(offset)
        offset += 2

        this.data = rawPacket.subarray(offset, offset + (this.length - 8))

        if (this.emitter)
            this.emitter.emit(this.decoderName, this)

        return this
    }

    toString() {
        const ret = `UDP ${this.sport} -> ${this.dport} len ${this.length}`
        if (Number(this.sport) === 53 || Number(this.dport) === 53) {
            // TODO: Implement DNS
            // ret += (new DNS().decode(this.data, 0, this.data.length).toString());
        }

        return ret
    }
}