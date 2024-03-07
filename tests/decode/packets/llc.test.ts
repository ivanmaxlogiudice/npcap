import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { LLCPacket } from '@/decode/packets'
import { IPv4 } from '@/decode/protocols'

describe('lLCPacket', () => {
    const buffer = Buffer.from(
        'aaaa030000000800' // LLC frame
        + '46c000200000400001021274c0a82101effffffa94040000' // ipv4 payload
        + '1600fa04effffffa' // igmpv2
        + '00000000',
        'hex',
    )
    const instance = new LLCPacket(buffer)

    describe('#constructor', () => {
        it('is a function and returns the instance', () => {
            expect(LLCPacket).toBeTypeOf('function')
            expect(instance).toBe(instance)
        })

        // it(`raises a ${LLCPacket.decoderName} event on decode`, () => {
        //     const handler = jest.fn()

        //     emitter.on(LLCPacket.decoderName, handler)
        //     instance = new LLCPacket(buffer, 0, emitter)

        //     expect(handler).toHaveBeenCalled()
        // })

        it('should decode packet', () => {
            expect(instance).toHaveProperty('dsap', 0xaa)
            expect(instance).toHaveProperty('ssap', 0xaa)
            expect(instance).toHaveProperty('control', 0x03)
            expect(instance).toHaveProperty('type', 2048)
            expect(instance.payload).toBeInstanceOf(IPv4)
        })
    })

    describe('#toString', () => {
        it('should return correct string representation', () => {
            expect(
                instance.toString(),
            ).toBe('dsap: 170 ssap: 170 IPv4 192.168.33.1 -> 239.255.255.250 flags [d] IGMP Membership Report')
        })
    })
})
