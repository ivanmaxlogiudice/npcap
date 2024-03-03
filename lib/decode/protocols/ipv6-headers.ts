import type { ProtocolsType } from '../ip-protocols'
import { protocols } from '../ip-protocols'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

export class NoNext {
    constructor(rawPacket: Buffer, offset: number = 0) {
        const remainingLength = rawPacket.length - offset

        if (remainingLength !== 0)
            throw new Error(`There is more packet left to be parse, but NoNext.decode was called with ${remainingLength} bytes left.`)
    }

    toString() {
        return ''
    }
}

export class HeaderExtension {
    static decoderName = 'header-extension'

    nextHeader: number
    headerLength: number
    payload: ProtocolsType

    constructor(rawPacket: Buffer, offset: number = 0, emitter?: EventEmitter) {
        const originalOffset = offset

        this.nextHeader = rawPacket[offset++]
        this.headerLength = (rawPacket[offset++] + 1) * 8

        offset = originalOffset + this.headerLength

        this.payload = protocols(this.nextHeader, undefined, rawPacket, offset, rawPacket.length - offset)

        if (emitter)
            emitter.emit(HeaderExtension.decoderName, this)
    }

    toString() {
        let ret = ''

        if (this.payload)
            ret += this.payload.constructor.name
        else
            ret += `proto ${this.nextHeader}`

        return `${ret} ${this.payload}`
    }
}
