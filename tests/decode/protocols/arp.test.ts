import { beforeEach, describe, expect, it } from 'bun:test'
import { Buffer } from 'node:buffer'
import EventEmitter from 'node:events'
import { Arp } from '../../../lib/decode/protocols/arp'

describe('ARP', () => {
    let emitter: EventEmitter
    let instance: Arp
    let buffer: Buffer

    beforeEach(() => {
        emitter = new EventEmitter()
        instance = new Arp(emitter)
        buffer = Buffer.from(
            '0001'
            + '0800060400010007'
            + '0daff454454cd801'
            + '000000000000454c'
            + 'dfd5',
            'hex',
        )
    })

    describe('#decode', () => {
        it('is a function and returns the instance', () => {
            expect(instance.decode).toBeTypeOf('function')
            expect(instance.decode(buffer)).toBe(instance)
        })

        it(`should decode ${Arp.decoderName} packet correctly`, () => {
            instance.decode(buffer)

            expect(instance).toHaveProperty('htype', 1) // Ethernet
            expect(instance).toHaveProperty('ptype', 0x0800) // IP
            expect(instance).toHaveProperty('hlen', 6)
            expect(instance).toHaveProperty('plen', 4)
            expect(instance).toHaveProperty('operation', 1)

            expect(instance).toHaveProperty('sender_ha.addr', [0x00, 0x07, 0x0d, 0xaf, 0xf4, 0x54])
            expect(instance).toHaveProperty('sender_pa.addr', [69, 76, 216, 1])
            expect(instance).toHaveProperty('target_ha.addr', [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            expect(instance).toHaveProperty('target_pa.addr', [69, 76, 223, 213])
        })
    })

    describe('#toString', () => {
        it('should return correct string representation', () => {
            // requests
            expect(
                instance.decode(buffer).toString(),
            ).toBe('request sender 00:07:0d:af:f4:54 69.76.216.1 target 00:00:00:00:00:00 69.76.223.213')

            // responses
            expect(
                instance.decode(Buffer.from('000108000604000200070daff454454cd801000000000000454cdfd5', 'hex')).toString(),
            ).toBe('reply sender 00:07:0d:af:f4:54 69.76.216.1 target 00:00:00:00:00:00 69.76.223.213')

            // unknown operations
            expect(
                instance.decode(Buffer.from('000108000604000f00070daff454454cd801000000000000454cdfd5', 'hex')).toString(),
            ).toBe('unknown sender 00:07:0d:af:f4:54 69.76.216.1 target 00:00:00:00:00:00 69.76.223.213')
        })
    })
})
