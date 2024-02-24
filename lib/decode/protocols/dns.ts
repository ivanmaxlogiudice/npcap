import { IPv4Addr } from './ipv4'
import { IPv6Addr } from './ipv6'
import type { Buffer } from 'node:buffer'
import type EventEmitter from 'node:events'

const DnsRrTypes: Record<number, string> = {
    0: 'Unknown (0)',
    1: 'A',
    2: 'NS',
    3: 'MD',
    4: 'MF',
    5: 'CNAME',
    6: 'SOA',
    7: 'MB',
    8: 'MG',
    9: 'MR',
    10: 'NULL',
    11: 'WKS',
    12: 'PTR',
    13: 'HINFO',
    14: 'MINFO',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA',
}

const DnsRrQtypes: Record<number, string> = {
    0: '*',
    252: 'AXFR',
    253: 'MAILB',
    254: 'MAILA',
    255: '*',
}

const DnsRrClasses: Record<number, string> = {
    0: 'Unknown (0)',
    1: 'IN',
    2: 'CS',
    3: 'CH',
    4: 'HS',
}

class DNSFlags {
    isResponse?: boolean
    opcode?: number
    isAuthority?: boolean
    isTruncated?: boolean
    isRecursionDesired?: boolean
    isRecursionAvailible?: boolean
    z?: number
    responseCode?: number

    decode(rawPacket: Buffer, offset: number = 0) {
        const firstByte = rawPacket[offset]
        const secondByte = rawPacket[offset + 1]

        this.isResponse = Boolean(firstByte & 0x80)
        this.opcode = (firstByte & 0x78) >> 3

        this.isAuthority = Boolean(firstByte & 0x04)
        this.isTruncated = Boolean(firstByte & 0x02)
        this.isRecursionDesired = Boolean(firstByte & 0x01)
        this.isRecursionAvailible = Boolean(secondByte & 0x80)
        this.z = secondByte & 0x70 >> 4
        this.responseCode = secondByte & 0x0F

        return this
    }

    toString() {
        return `{ isResponse: ${this.isResponse} opcode: ${this.opcode} isAuthority: ${this.isAuthority}} isTruncated: ${this.isTruncated}`
            + ` isRecursionDesired: ${this.isRecursionDesired} isRecursionAvailible: ${this.isRecursionAvailible} z: ${this.z} responseCode: ${this.responseCode} }`
    }
}

class DNSRR {
    ttl?: number
    rdata?: string
    rdlength?: number
    data?: IPv6Addr

    constructor(
        public isQuestion: boolean,
        public name: string,
        public type: number,
        public classNum: number,
    ) { }

    typeToString(type: number) {
        return DnsRrTypes[type] || `Unknown (${type})`
    }

    qTypeToString(num: number) {
        if (num in DnsRrQtypes)
            return DnsRrQtypes[num]
        else
            return this.typeToString(num)
    }

    classToString(num: number) {
        return DnsRrClasses[num] || `Unknown (${num})`
    }

    qClassToString(num: number) {
        return num === 255 ? '*' : this.classToString(num)
    }

    toString() {
        let ret = `${this.name} `
        if (this.isQuestion)
            ret += `${this.qTypeToString(this.type)} ${this.qClassToString(this.classNum)}`
        else
            ret += `${this.typeToString(this.type)} ${this.classToString(this.classNum)} ${this.ttl} ${this.rdata}`

        return ret
    }
}

class DNSRRSet {
    rrs: DNSRR[]

    constructor(count: number) {
        this.rrs = Array.from({ length: count })
    }

    toString() {
        return this.rrs.join(', ')
    }
}

export class DNS {
    static decoderName = 'dns'

    emitter?: EventEmitter
    rawPacket!: Buffer
    offset: number = 0
    id?: number
    header!: DNSFlags
    qdcount!: number
    ancount!: number
    nscount!: number
    arcount!: number
    question?: DNSRRSet
    answer?: DNSRRSet
    authority?: DNSRRSet
    additional?: DNSRRSet
    _error?: string

    constructor(emitter?: EventEmitter) {
        this.emitter = emitter
    }

    // http://tools.ietf.org/html/rfc1035
    decode(rawPacket: Buffer, offset: number = 0) {
        // these 2 fields will be deleted soon.
        this.rawPacket = rawPacket
        this.offset = offset

        this.id = rawPacket.readUInt16BE(offset) // 0, 1
        this.header = new DNSFlags().decode(rawPacket, offset + 2)
        this.qdcount = rawPacket.readUInt16BE(offset + 4) // 4, 5
        this.ancount = rawPacket.readUInt16BE(offset + 6) // 6, 7
        this.nscount = rawPacket.readUInt16BE(offset + 8) // 8, 9
        this.arcount = rawPacket.readUInt16BE(offset + 10) // 10, 11
        this.offset += 12

        this.question = this.#decode_RRs(this.qdcount, true)
        this.answer = this.#decode_RRs(this.ancount, false)
        this.authority = this.#decode_RRs(this.nscount, false)
        this.additional = this.#decode_RRs(this.arcount, false)

        if (this.emitter)
            this.emitter.emit(DNS.decoderName, this)

        return this
    }

    #decode_RRs(count: number, isQuestion: boolean) {
        if (count > 100) {
            this._error = `Malformed DNS packet: too many RRs at offset ${this.offset}`
            return undefined
        }

        const ret = new DNSRRSet(count)
        for (let i = 0; i < count; i++)
            ret.rrs[i] = this.#decode_RR(isQuestion)

        return ret
    }

    #decode_RR(isQuestion: boolean) {
        if (this.offset > this.rawPacket.length)
            throw new Error(`Malformed DNS RR. Offset is beyond packet len (decode_RR) :${this.offset} packet_len:${this.rawPacket.length}`)

        const name = this.#readName()

        const type = this.rawPacket.readUInt16BE(this.offset)
        this.offset += 2

        const classNum = this.rawPacket.readUInt16BE(this.offset)
        this.offset += 2

        const rr = new DNSRR(isQuestion, name, type, classNum)

        if (isQuestion)
            return rr

        rr.ttl = this.rawPacket.readUInt32BE(this.offset)
        this.offset += 4

        rr.rdlength = this.rawPacket.readUInt16BE(this.offset)
        this.offset += 2

        if (rr.type === 1 && rr.classNum === 1 && rr.rdlength) { // A, IN
            rr.rdata = new IPv4Addr().decode(this.rawPacket, this.offset).toString()
        }
        else if (rr.type === 2 && rr.classNum === 1) { // NS, IN
            rr.rdata = this.#readName()
            this.offset -= rr.rdlength // readName moves offset
        }
        else if (rr.type === 28 && rr.classNum === 1 && rr.rdlength === 16) {
            rr.data = new IPv6Addr().decode(this.rawPacket, this.offset)
        }
        // TODO - decode other rr types

        this.offset += rr.rdlength

        return rr
    }

    #readName() {
        let result = ''
        let lenOrPtr
        let pointer_follows = 0
        let pos = this.offset

        // eslint-disable-next-line no-cond-assign
        while ((lenOrPtr = this.rawPacket[pos]) !== 0x00) {
            if ((lenOrPtr & 0xC0) === 0xC0) {
                // pointer is bottom 6 bits of current byte, plus all 8 bits of next byte
                pos = ((lenOrPtr & ~0xC0) << 8) | this.rawPacket[pos + 1]
                pointer_follows++
                if (pointer_follows === 1)
                    this.offset += 2

                if (pointer_follows > 5)
                    throw new Error(`invalid DNS RR: too many compression pointers found at offset ${pos}`)
            }
            else {
                if (result.length > 0)
                    result += '.'

                if (lenOrPtr > 63)
                    throw new Error(`invalid DNS RR: length is too large at offset ${pos}`)

                pos++
                for (let i = pos; i < (pos + lenOrPtr) && i < this.rawPacket.length; i++) {
                    if (i > this.rawPacket.length)
                        throw new Error(`invalid DNS RR: read beyond end of packet at offset ${i}`)

                    const ch = this.rawPacket[i]
                    result += String.fromCharCode(ch)
                }
                pos += lenOrPtr

                if (pointer_follows === 0)
                    this.offset = pos
            }
        }

        if (pointer_follows === 0)
            this.offset++

        return result
    }

    toString() {
        let ret = ' DNS '

        ret += this.header.toString()

        if (this.qdcount > 0)
            ret += `\n  question:${this.question?.rrs[0]}`

        if (this.ancount > 0)
            ret += `\n  answer:${this.answer}`

        if (this.nscount > 0)
            ret += `\n  authority:${this.authority}`

        if (this.arcount > 0)
            ret += `\n  additional:${this.additional}`

        return ret
    }
}
