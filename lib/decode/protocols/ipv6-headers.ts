import { protocols } from '../protocols'
import type { Buffer } from 'node:buffer'

export class NoNext {
    error?: string

    decode(rawPacket: Buffer, offset: number = 0) {
        const remainingLength = rawPacket.length - offset

        if (remainingLength !== 0)
            this.error = `There is more packet left to be parse, but NoNext.decode was called with ${remainingLength} bytes left.`

        return this
    }

    toString() {
        return ''
    }
}

export class HeaderExtension {
    payload?: any
    nextHeader?: number
    headerLength?: number
    protocolName?: string

    decode(rawPacket: Buffer, offset: number = 0) {
        const originalOffset = offset
        this.nextHeader = rawPacket[offset++]
        this.headerLength = (rawPacket[offset++] + 1) * 8

        offset = originalOffset + this.headerLength

        this.payload = protocols(this.nextHeader, undefined, rawPacket, offset, rawPacket.length - offset)
        if (this.payload === undefined)
            this.protocolName = 'Unknown'

        return this
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
