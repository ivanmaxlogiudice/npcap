import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'
import { ICMP, IGMP, IPv4, IPv6, Tcp, Udp } from '.'
import { protocols } from '../ip-protocols'
import type { ProtocolsType } from '../ip-protocols'

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

    isHeaderExtension(): this is { payload: HeaderExtension } {
        return this.payload instanceof HeaderExtension
    }

    isICMP(): this is { payload: ICMP } {
        return this.payload instanceof ICMP
    }

    isIGMP(): this is { payload: IGMP } {
        return this.payload instanceof IGMP
    }

    isIPv4(): this is { payload: IPv4 } {
        return this.payload instanceof IPv4
    }

    isTcp(): this is { payload: Tcp } {
        return this.payload instanceof Tcp
    }

    isUdp(): this is { payload: Udp } {
        return this.payload instanceof Udp
    }

    isIPv6(): this is { payload: IPv6 } {
        return this.payload instanceof IPv6
    }

    isNoNext(): this is { payload: NoNext } {
        return this.payload instanceof NoNext
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
