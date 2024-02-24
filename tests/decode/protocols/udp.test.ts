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
        it('is a function', () => {
            expect(instance.decode).toBeTypeOf('function')
        })

        it('returns the instance', () => {
            expect(instance.decode(buffer, 0)).toBe(instance)
        })

        it('raises a Udp event on decode', () => {
            const handler = jest.fn()

            emitter.on(instance.decoderName, handler)
            instance.decode(buffer, 0)

            expect(handler).toHaveBeenCalled()
        })

        it('sets #sport to the source port', () => {
            expect(instance.decode(buffer, 0)).toHaveProperty('sport', 1234)
        })

        it('sets #dport to the destination port', () => {
            expect(instance.decode(buffer, 0)).toHaveProperty('dport', 1235)
        })

        it('sets #length to the length of the payload', () => {
            expect(instance.decode(buffer, 0)).toHaveProperty('length', 9)
        })

        it('sets #data to the payload', () => {
            expect(instance.decode(buffer, 0)).toHaveProperty('data', Buffer.from('30', 'hex'))
        })

        it('sets #checksum to the checksum', () => {
            expect(instance.decode(buffer, 0)).toHaveProperty('checksum', 0xdf03)
        })
    })

    describe('#toString()', () => {
        it('is a function', () => {
            expect(instance.toString).toBeTypeOf('function')
        })
    })
})
