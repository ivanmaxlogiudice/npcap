import { Buffer } from 'node:buffer'
import { IPv6, IPv6Addr } from '@/decode/protocols'
import { describe, expect, it } from 'vitest'

describe('iPv6Addr', () => {
    const buffer = Buffer.from('000102030405060708090A0B0C0D0E0F', 'hex')
    const instance = new IPv6Addr(buffer)

    describe('#constructor', () => {
        it('is a function', () => {
            expect(instance).toBeTypeOf('object')
        })

        it('should decode address correctly', () => {
            expect(instance).toHaveProperty('addr', [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        })
    })

    describe('#toString()', () => {
        it('is a function', () => {
            expect(instance.toString).toBeTypeOf('function')
        })

        it('should return correct string representation', () => {
            expect(instance.toString()).toBe('0001:0203:0405:0607:0809:0a0b:0c0d:0e0f')
        })
    })
})

describe('iPv6', () => {
    const buffer = Buffer.from(
        '61298765' // version=6, trafficClass=0x12, labelflow=0,
        + '0000' // payloadLength =0
        + '3b' // No next header
        + '00' // hopLimit=0
        + 'fe80000000000000708dfe834114a512' // src address
        + '2001000041379e508000f12ab9c82815', // dest address
        'hex',
    )
    const instance = new IPv6(buffer)

    describe('#constructor', () => {
        it('is a function and returns the instance', () => {
            expect(instance).toBeTypeOf('object')
            expect(instance).toBe(instance)
        })

        // it(`raises a ${IPv6.decoderName} event on decode`, () => {
        //     const handler = jest.fn()

        //     emitter.on(IPv6.decoderName, handler)
        //     instance.decode(buffer)

        //     expect(handler).toHaveBeenCalled()
        // })

        it('should decode IPv6 packet correctly', () => {
            expect(instance).toHaveProperty('version', 6)
            expect(instance).toHaveProperty('trafficClass', 0x12)
            expect(instance).toHaveProperty('flowLabel', 0x98765)
            expect(instance).toHaveProperty('payloadLength', 0)
            expect(instance).toHaveProperty('nextHeader', 59)
            expect(instance).toHaveProperty('hopLimit', 0)

            expect(instance).toHaveProperty('saddr.addr', [0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x8D, 0xFE, 0x83, 0x41, 0x14, 0xA5, 0x12])
            expect(instance).toHaveProperty('daddr.addr', [0x20, 0x01, 0x00, 0x00, 0x41, 0x37, 0x9E, 0x50, 0x80, 0x00, 0xF1, 0x2A, 0xB9, 0xC8, 0x28, 0x15])

            // TODO: Implement IPv6 Headers
            // expect(instance).toHaveProperty('payload', 0NoNext)
        })

        it('should throw an error on unknown protocol', () => {
            expect(() => new IPv6(Buffer.from(
                '60000000' // version=6, trafficClass=0x12, labelflow=0,
                + '0000' // payloadLength =0
                + 'ff' // a next header type which is not supported
                + '00' // hopLimit=0
                + 'fe80000000000000708dfe834114a512' // src address
                + '2001000041379e508000f12ab9c82815' // dest address
                + '1600fa04effffffa',
                'hex',
            ))).toThrow('Dont know how to decode protocol 255')
        })
    })

    describe('#toString', () => {
        it('is a function', () => {
            expect(instance.toString).toBeTypeOf('function')
        })

        it('should return correct string representation', () => {
            // IGMP
            expect(
                new IPv6(Buffer.from(
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
