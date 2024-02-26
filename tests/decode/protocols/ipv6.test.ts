import { beforeEach, describe, expect, it, jest } from 'bun:test'
import { Buffer } from 'node:buffer'
import EventEmitter from 'node:events'
import { IPv6, IPv6Addr } from '@/decode/protocols'

describe('IPv6Addr', () => {
    let instance: IPv6Addr
    let buffer: Buffer

    beforeEach(() => {
        instance = new IPv6Addr()
        buffer = Buffer.from('000102030405060708090A0B0C0D0E0F', 'hex')
    })

    describe('#decode', () => {
        it('is a function', () => {
            expect(instance.decode).toBeTypeOf('function')
        })

        it('should decode address correctly', () => {
            expect(instance.decode(buffer)).toHaveProperty('addr', [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        })
    })

    describe('#toString()', () => {
        it('is a function', () => {
            expect(instance.toString).toBeTypeOf('function')
        })

        it('should return correct string representation', () => {
            expect(instance.decode(buffer).toString()).toBe('0001:0203:0405:0607:0809:0a0b:0c0d:0e0f')
        })
    })
})

describe('IPv6', () => {
    let emitter: EventEmitter
    let instance: IPv6
    let buffer: Buffer

    beforeEach(() => {
        emitter = new EventEmitter()
        instance = new IPv6(emitter)
        buffer = Buffer.from(
            '61298765' // version=6, trafficClass=0x12, labelflow=0,
            + '0000' // payloadLength =0
            + '3b' // No next header
            + '00' // hopLimit=0
            + 'fe80000000000000708dfe834114a512' // src address
            + '2001000041379e508000f12ab9c82815', // dest address
            'hex',
        )
    })

    describe('#decode', () => {
        it('is a function and returns the instance', () => {
            expect(instance.decode).toBeTypeOf('function')
            expect(instance.decode(buffer)).toBe(instance)
        })

        it(`raises a ${IPv6.decoderName} event on decode`, () => {
            const handler = jest.fn()

            emitter.on(IPv6.decoderName, handler)
            instance.decode(buffer)

            expect(handler).toHaveBeenCalled()
        })

        it('should decode IPv6 packet correctly', () => {
            instance.decode(buffer)

            expect(instance).toHaveProperty('version', 6)
            expect(instance).toHaveProperty('trafficClass', 0x12)
            expect(instance).toHaveProperty('flowLabel', 0x98765)
            expect(instance).toHaveProperty('payloadLength', 0)
            expect(instance).toHaveProperty('nextHeader', 59)
            expect(instance).toHaveProperty('hopLimit', 0)

            expect(instance).toHaveProperty('saddr.addr', [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x8d, 0xfe, 0x83, 0x41, 0x14, 0xa5, 0x12])
            expect(instance).toHaveProperty('daddr.addr', [0x20, 0x01, 0x00, 0x00, 0x41, 0x37, 0x9e, 0x50, 0x80, 0x00, 0xf1, 0x2a, 0xb9, 0xc8, 0x28, 0x15])

            // TODO: Implement IPv6 Headers
            // expect(instance).toHaveProperty('payload', 0NoNext)
        })
    })

    describe('#toString', () => {
        it('is a function', () => {
            expect(instance.toString).toBeTypeOf('function')
        })

        it('should return correct string representation', () => {
            // unsupported
            expect(
                instance.decode(Buffer.from(
                    '60000000' // version=6, trafficClass=0x12, labelflow=0,
                    + '0000' // payloadLength =0
                    + 'ff' // a next header type which is not supported
                    + '00' // hopLimit=0
                    + 'fe80000000000000708dfe834114a512' // src address
                    + '2001000041379e508000f12ab9c82815' // dest address
                    + '1600fa04effffffa',
                    'hex',
                )).toString(),
            ).toBe('fe80:0000:0000:0000:708d:fe83:4114:a512 -> 2001:0000:4137:9e50:8000:f12a:b9c8:2815 proto 255 undefined')

            // IGMP
            expect(
                instance.decode(Buffer.from(
                    '60000000' // version=6, trafficClass=0x12, labelflow=0,
                    + '0000' // payloadLength =0
                    + '02' // IGMP next
                    + '00' // hopLimit=0
                    + 'fe80000000000000708dfe834114a512' // src address
                    + '2001000041379e508000f12ab9c82815' // dest address
                    + '1600fa04effffffa',
                    'hex',
                )).toString(),
            ).toBe('fe80:0000:0000:0000:708d:fe83:4114:a512 -> 2001:0000:4137:9e50:8000:f12a:b9c8:2815 IGMP Membership Report')
        })
    })
})
