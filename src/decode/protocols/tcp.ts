import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class TCPFlags {
    nonce: boolean
    cwr: boolean
    ece: boolean
    urg: boolean
    ack: boolean
    psh: boolean
    rst: boolean
    syn: boolean
    fin: boolean

    constructor(firstByte: number, secondByte: number) {
        this.nonce = Boolean(firstByte & 1)
        this.cwr = Boolean(secondByte & 128)
        this.ece = Boolean(secondByte & 64)
        this.urg = Boolean(secondByte & 32)
        this.ack = Boolean(secondByte & 16)
        this.psh = Boolean(secondByte & 8)
        this.rst = Boolean(secondByte & 4)
        this.syn = Boolean(secondByte & 2)
        this.fin = Boolean(secondByte & 1)

        return this
    }

    toString() {
        let ret = '['

        if (this.cwr) ret += 'c'
        if (this.ece) ret += 'e'
        if (this.urg) ret += 'u'
        if (this.ack) ret += 'a'
        if (this.psh) ret += 'p'
        if (this.rst) ret += 'r'
        if (this.syn) ret += 's'
        if (this.fin) ret += 'f'

        ret += ']'

        return ret
    }
}

export class TCPOptions {
    /**
     * Maximum segment size.
     *
     * Largest amount of data, specified in bytes, that TCP is willing to receive in a single segment.
     */
    mss?: number
    windowScale?: number
    sackOk?: boolean
    sack?: Array<number[]>
    timestamp?: number
    echo?: number

    decode(rawPacket: Buffer, offset: number, len: number) {
        const endOffset = offset + len

        while (offset < endOffset) {
            switch (rawPacket[offset]) {
                case 0: // End of options list
                    offset = endOffset
                    break
                case 1: // No operation
                    offset += 1
                    break
                case 2: // Maximum segment size (length: 4)
                    offset += 2
                    this.mss = rawPacket.readUInt16BE(offset)
                    offset += 2
                    break
                case 3: // Window scale (length: 3)
                    offset += 2
                    this.windowScale = rawPacket[offset]
                    offset += 1
                    break
                case 4: // SACK permitted (length: 2)
                    this.sackOk = true
                    offset += 2
                    break
                case 5: // SACK
                    this.sack = []
                    offset += 1

                    switch (rawPacket[offset]) {
                        case 10:
                            offset += 1
                            this.sack.push([rawPacket.readUInt32BE(offset), rawPacket.readUInt32BE(offset + 4)])
                            offset += 8
                            break
                        case 18:
                            offset += 1
                            this.sack.push([rawPacket.readUInt32BE(offset), rawPacket.readUInt32BE(offset + 4)])
                            offset += 8
                            this.sack.push([rawPacket.readUInt32BE(offset), rawPacket.readUInt32BE(offset + 4)])
                            offset += 8
                            break
                        case 26:
                            offset += 1
                            this.sack.push([rawPacket.readUInt32BE(offset), rawPacket.readUInt32BE(offset + 4)])
                            offset += 8
                            this.sack.push([rawPacket.readUInt32BE(offset), rawPacket.readUInt32BE(offset + 4)])
                            offset += 8
                            this.sack.push([rawPacket.readUInt32BE(offset), rawPacket.readUInt32BE(offset + 4)])
                            offset += 8
                            break
                        case 34:
                            offset += 1
                            this.sack.push([rawPacket.readUInt32BE(offset), rawPacket.readUInt32BE(offset + 4)])
                            offset += 8
                            this.sack.push([rawPacket.readUInt32BE(offset), rawPacket.readUInt32BE(offset + 4)])
                            offset += 8
                            this.sack.push([rawPacket.readUInt32BE(offset), rawPacket.readUInt32BE(offset + 4)])
                            offset += 8
                            this.sack.push([rawPacket.readUInt32BE(offset), rawPacket.readUInt32BE(offset + 4)])
                            offset += 8
                            break
                        default:
                            console.log(`Invalid TCP SACK option length ${rawPacket[offset + 1]}`)
                            offset = endOffset
                    }

                    break
                case 8: // Timestamp (length: 10)
                    offset += 2

                    this.timestamp = rawPacket.readUInt32BE(offset)
                    offset += 4

                    this.echo = rawPacket.readUInt32BE(offset)
                    offset += 4
                    break
                case 254:
                case 255:
                    offset += rawPacket.readUInt8(offset + 1)
                    break
                default:
                    throw new Error(`Don't know how to process TCP option ${rawPacket[offset]}`)
            }
        }

        return this
    }

    toString() {
        let ret = ''
        if (this.mss)
            ret += `mss:${this.mss} `

        if (this.windowScale)
            ret += `scale:${this.windowScale}(${2 ** this.windowScale}) `

        if (this.sackOk)
            ret += 'sackOk' + ' '

        if (this.sack)
            ret += `sack:${this.sack.join(',')} `

        if (ret.length === 0)
            ret = '. '

        return `[${ret.slice(0, -1)}]`
    }
}

export class Tcp {
    static decoderName = 'tcp'

    sport: number
    dport: number
    seqno: number
    ackno: number
    headerLength: number
    flags: TCPFlags
    windowSize: number
    checksum: number
    urgentPointer: number
    options?: TCPOptions
    dataLength: number
    data: Buffer | null

    // http://en.wikipedia.org/wiki/Transmission_Control_Protocol
    constructor(rawPacket: Buffer, offset: number = 0, len: number = 0, emitter?: EventEmitter) {
        const originalOffset = offset

        this.sport = rawPacket.readUInt16BE(offset) // 0, 1
        offset += 2

        this.dport = rawPacket.readUInt16BE(offset) // 2, 3
        offset += 2

        this.seqno = rawPacket.readUInt32BE(offset) // 4, 5, 6, 7
        offset += 4

        this.ackno = rawPacket.readUInt32BE(offset) // 8, 9, 10, 11
        offset += 4

        // The first 4 bits of the next header * 4 tells use the length of the header.
        this.headerLength = (rawPacket[offset] & 0xf0) >> 2

        this.flags = new TCPFlags(rawPacket[offset], rawPacket[offset + 1])
        offset += 2

        this.windowSize = rawPacket.readUInt16BE(offset) // 14, 15
        offset += 2

        this.checksum = rawPacket.readUInt16BE(offset) // 16, 17
        offset += 2

        this.urgentPointer = rawPacket.readUInt16BE(offset) // 18, 19
        offset += 2

        this.options = new TCPOptions()
        const optionsLen = this.headerLength - (offset - originalOffset)
        if (optionsLen > 0) {
            this.options.decode(rawPacket, offset, optionsLen)
            offset += optionsLen
        }

        this.dataLength = len - this.headerLength
        if (this.dataLength > 0) {
            // add a buffer slice pointing to the data area of this TCP packet.
            // Note that this does not make a copy, so ret.data is only valid for this current
            // trip through the capture loop.
            this.data = rawPacket.subarray(offset, offset + this.dataLength)
        }
        else {
            // null indicated the value was set. Where as undefined
            // means the value was never set. Since there is no data
            // we explicity want to communicate this to consumers.
            this.data = null
        }

        if (emitter)
            emitter.emit(Tcp.decoderName, this)
    }

    toString() {
        let ret = `${this.sport} -> ${this.dport} seq ${this.seqno} ack ${this.ackno} flags ${this.flags} win ${this.windowSize} csum ${this.checksum}`

        if (this.urgentPointer)
            ret += ` urg ${this.urgentPointer}`

        ret += ` ${this.options} len ${this.dataLength}`
        return ret
    }
}
