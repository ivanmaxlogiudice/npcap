import { beforeEach, describe, expect, it } from 'bun:test'
import { Buffer } from 'node:buffer'
import EventEmitter from 'node:events'
import { DNS } from '../../../lib/decode/protocols/dns'

describe('DNS', () => {
    let emitter: EventEmitter
    let instance: DNS
    let buffer: Buffer

    beforeEach(() => {
        emitter = new EventEmitter()
        instance = new DNS(emitter)
        buffer = Buffer.from(
            '311f' // transaction id
            + '0100' // flags
            + '0001' // 1 Question
            + '0000' // 0 answer RRs
            + '0000' // 0 authority RRS
            + '0000' // 0 additional RRs
            + '01320131033136380331393207696e2d61646472046172706100' // name:2.1.168.192.in-addr.arpa
            + '000c' // type PTR
            + '0001', // Class IN
            'hex',
        )
    })

    describe('#decode', () => {
        it('is a function and returns the instance', () => {
            expect(instance.decode).toBeTypeOf('function')
            expect(instance.decode(buffer)).toBe(instance)
        })

        it('should decode DNS packet correctly', () => {
            instance.decode(buffer)

            expect(instance).toHaveProperty('id', 0x311f)

            expect(instance).toHaveProperty('header.isResponse', false)
            expect(instance).toHaveProperty('header.opcode', 0)
            expect(instance).toHaveProperty('header.isAuthority', false)
            expect(instance).toHaveProperty('header.isRecursionDesired', true)
            expect(instance).toHaveProperty('header.isRecursionAvailible', false)
            expect(instance).toHaveProperty('header.z', 0)
            expect(instance).toHaveProperty('header.responseCode', 0)
        })
    })

    describe('#toString', () => {
        it('should return correct string representation', () => {
            expect(instance.decode(buffer).toString()).toBe(' DNS { isResponse: false opcode: 0 isAuthority: false} isTruncated: false isRecursionDesired: true isRecursionAvailible: false z: 0 responseCode: 0 }\n  question:2.1.168.192.in-addr.arpa PTR IN')
        })
    })
})
