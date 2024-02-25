import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class RadioPacket {
    static decoderName = 'radio-packet'
    static globalCache: Record<string, string> = {}

    headerVersion!: number
    headerPad!: number
    headerLength!: number
    presentFields!: number | bigint
    fields?: any

    constructor(
        public emitter?: EventEmitter,
    ) {}

    /**
     * https://www.radiotap.org/
     *
     * Data is specified in little endian (LE) byte-order.
     */
    decode(rawPacket: Buffer, offset: number = 0) {
        this.headerVersion = rawPacket[offset++]
        if (this.headerVersion === 0)
            console.warn(`NpcapPacket: RadioPacket() - Unknown radiotap version: ${this.headerVersion}`)

        this.headerPad = rawPacket[offset++]

        this.headerLength = rawPacket.readUInt16LE(offset)
        offset += 2

        this.presentFields = rawPacket.readUInt32LE(offset)
        offset += 4

        // Use BigInt if the extension bit is set.
        if (this.presentFields >> 31) {
            this.presentFields = BigInt(this.presentFields)

            let bitIndex = 32n // Start from the 32nd bit
            while (this.presentFields >> (bitIndex - 1n)) {
                this.presentFields ^= 1n << (bitIndex - 1n) // Clear the current bit

                const value = rawPacket.readUInt32LE(offset)
                offset += 4

                this.presentFields |= BigInt(value) << bitIndex // Set the bits with value read
                bitIndex += 32n // Move to the next set of 32 bits
            }
        }

        // TODO: Missing implementation
        // https://github.com/plus100kt/node_pcap/blob/master/decode/ieee802.11/radio_packet.js#L55

        if (this.emitter)
            this.emitter.emit(RadioPacket.decoderName, this)

        return this
    }
}
