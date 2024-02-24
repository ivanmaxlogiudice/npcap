import { beforeEach, describe, expect, it, jest } from 'bun:test'
import { Buffer } from 'node:buffer'
import EventEmitter from 'node:events'
import { Udp } from '../../../lib/decode/protocols/udp'

describe('Udp', () => {
    let emitter: EventEmitter
    let instance: Udp
    let buffer: Buffer

    beforeEach(() => {
        emitter = new EventEmitter()
        instance = new Udp(emitter)
        buffer = Buffer.from(
            '04d2' // source port 1234
            + '04d3' // dst port 1235
            + '0009' // length
            + 'df03' // checksum (this on is bad)
            + '30',
            'hex',
        )
    })

    describe('#decode', () => {
        it('is a function and returns the instance', () => {
            expect(instance.decode).toBeTypeOf('function')
            expect(instance.decode(buffer, 0)).toBe(instance)
        })

        it(`raises a ${Udp.name} event on decode`, () => {
            const handler = jest.fn()

            emitter.on(instance.decoderName, handler)
            instance.decode(buffer, 0)

            expect(handler).toHaveBeenCalled()
        })

        it('should decode Udp packet correctly', () => {
            instance.decode(buffer, 0)

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
            expect(instance.decode(buffer, 0).toString()).toBe('UDP 1234 -> 1235 len 9')
        })
    })
})
