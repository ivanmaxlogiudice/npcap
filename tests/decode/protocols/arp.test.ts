import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { Arp } from '@/decode/protocols'

describe('aRP', () => {
    const buffer = Buffer.from(
        '0001'
        + '0800060400010007'
        + '0daff454454cd801'
        + '000000000000454c'
        + 'dfd5',
        'hex',
    )
    const instance = new Arp(buffer)

    describe('#constructor', () => {
        it('is a function and returns the instance', () => {
            expect(instance).toBeTypeOf('object')
            expect(instance).toBe(instance)
        })

        it(`should decode ${Arp.decoderName} packet correctly`, () => {
            expect(instance).toHaveProperty('htype', 1) // Ethernet
            expect(instance).toHaveProperty('ptype', 0x0800) // IP
            expect(instance).toHaveProperty('hlen', 6)
            expect(instance).toHaveProperty('plen', 4)
            expect(instance).toHaveProperty('operation', 1)

            expect(instance).toHaveProperty('sha.addr', [0x00, 0x07, 0x0d, 0xaf, 0xf4, 0x54])
            expect(instance).toHaveProperty('spa.addr', [69, 76, 216, 1])
            expect(instance).toHaveProperty('tha.addr', [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            expect(instance).toHaveProperty('tpa.addr', [69, 76, 223, 213])
        })
    })

    describe('#toString', () => {
        it('should return correct string representation', () => {
            // requests
            expect(
                instance.toString(),
            ).toBe('request sender 00:07:0d:af:f4:54 69.76.216.1 target 00:00:00:00:00:00 69.76.223.213')

            // responses
            expect(
                new Arp(Buffer.from('000108000604000200070daff454454cd801000000000000454cdfd5', 'hex')).toString(),
            ).toBe('reply sender 00:07:0d:af:f4:54 69.76.216.1 target 00:00:00:00:00:00 69.76.223.213')

            // unknown operations
            expect(
                new Arp(Buffer.from('000108000604000f00070daff454454cd801000000000000454cdfd5', 'hex')).toString(),
            ).toBe('unknown sender 00:07:0d:af:f4:54 69.76.216.1 target 00:00:00:00:00:00 69.76.223.213')
        })
    })
})
