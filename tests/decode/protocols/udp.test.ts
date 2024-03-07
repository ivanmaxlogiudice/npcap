import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { Udp } from '@/decode/protocols'

describe('udp', () => {
    const buffer = Buffer.from(
        '04d2' // source port 1234
        + '04d3' // dst port 1235
        + '0009' // length
        + 'df03' // checksum (this on is bad)
        + '30',
        'hex',
    )
    const instance = new Udp(buffer)

    describe('#constructor', () => {
        it('is a function and returns the instance', () => {
            expect(instance).toBeTypeOf('object')
            expect(instance).toBe(instance)
        })

        // it(`raises a ${Udp.decoderName} event on decode`, () => {
        //     const handler = jest.fn()

        //     emitter.on(Udp.decoderName, handler)
        //     instance.decode(buffer)

        //     expect(handler).toHaveBeenCalled()
        // })

        it('should decode Udp packet correctly', () => {
            expect(instance).toHaveProperty('sport', 1234)
            expect(instance).toHaveProperty('dport', 1235)
            expect(instance).toHaveProperty('length', 9)
            expect(instance).toHaveProperty('data', Buffer.from('30', 'hex'))
            expect(instance).toHaveProperty('checksum', 0xdf03)
        })
    })

    describe('#toString()', () => {
        it('is a function', () => {
            expect(instance.toString).toBeTypeOf('function')
        })

        it('should return correct string representation', () => {
            expect(new Udp(buffer).toString()).toBe('UDP 1234 -> 1235 len 9')
        })
    })
})
