import { beforeEach, describe, expect, it, jest } from 'bun:test'
import { Buffer } from 'node:buffer'
import EventEmitter from 'node:events'
import { IGMP } from '../../../lib/decode/protocols/iGMP'
import { int8_to_hex } from '../../../lib/decode/utils'

describe('IGMP', () => {
    let emitter: EventEmitter
    let instance: IGMP
    let buffer: Buffer

    beforeEach(() => {
        emitter = new EventEmitter()
        instance = new IGMP(emitter)
        buffer = Buffer.from('0102030405060708', 'hex')
    })

    describe('#decode', () => {
        it('is a function and returns the instance', () => {
            expect(instance.decode).toBeTypeOf('function')
            expect(instance.decode(buffer)).toBe(instance)
        })

        it(`raises a ${IGMP.name} event on decode`, () => {
            const handler = jest.fn()

            emitter.on(instance.decoderName, handler)
            instance.decode(buffer)

            expect(handler).toHaveBeenCalled()
        })

        it('should decode IGMP packet correctly', () => {
            instance.decode(buffer)

            expect(instance).toHaveProperty('type', 1)
            expect(instance).toHaveProperty('maxResponseTime', 2)
            expect(instance).toHaveProperty('checksum', 772)
            expect(instance).toHaveProperty('groupAddress.addr', [5, 6, 7, 8])
        })

        it('set the right igmp version', () => {
            expect(instance.decode(Buffer.from('1102030405060708', 'hex'))).toHaveProperty('version', 3)
            expect(instance.decode(Buffer.from('1202030405060708', 'hex'))).toHaveProperty('version', 1)
            expect(instance.decode(Buffer.from('1602030405060708', 'hex'))).toHaveProperty('version', 2)
            expect(instance.decode(Buffer.from('1702030405060708', 'hex'))).toHaveProperty('version', 2)
            expect(instance.decode(Buffer.from('2202030405060708', 'hex'))).toHaveProperty('version', 3)
        })
    })

    describe('#toString', () => {
        const verifyToString = function verifyToString(type, result) {
            instance.decode(Buffer.from(`${int8_to_hex[type]}000000000000"`, 'hex'), 0)

            expect(instance.toString()).toBe(result)
        }

        it('should return correct string representation', () => {
            // verifyToString(type, string)
            verifyToString(0x11, 'Membership Query')
            verifyToString(0x12, 'Membership Report')
            verifyToString(0x16, 'Membership Report')
            verifyToString(0x17, 'Leave Group')
            verifyToString(0x22, 'Membership Report')

            // Default handler
            verifyToString(0x01, 'type 1')
        })
    })
})
