import { beforeEach, describe, expect, it } from 'bun:test'
import { Buffer } from 'node:buffer'
import { HeaderExtension, NoNext } from '../../../lib/decode/protocols/ipv6-headers'

describe('NoNext', () => {
    let instance: NoNext
    let buffer: Buffer

    beforeEach(() => {
        instance = new NoNext()
        buffer = Buffer.from('', 'hex')
    })

    describe('#decode', () => {
        it('is a function and returns instance', () => {
            expect(instance.decode).toBeTypeOf('function')
            expect(instance.decode(buffer)).toBe(instance)
        })

        it('decodes nothing', () => {
            expect(instance.decode(buffer)).toHaveProperty('error', undefined)
        })

        it('sets #error when something is wrong', () => {
            expect(instance.decode(Buffer.from('00', 'hex'))).toHaveProperty('error')
        })
    })

    describe('#toString', () => {
        it('is a function', () => {
            expect(instance.toString).toBeTypeOf('function')
        })

        it('returns ""', () => {
            expect(instance.decode(buffer).toString()).toBe('')
        })
    })
})

describe('HeaderExtension', () => {
    let instance: HeaderExtension
    let buffer: Buffer

    beforeEach(() => {
        instance = new HeaderExtension()
        buffer = Buffer.from(
            '3B' // No next will be the next header
            + '01' // the length of the the header in 8 byte units - 8bytes
            + '0000000000000000'
            + '000000000000', // details about the current header
            'hex',
        )
    })

    describe('#decode', () => {
        it('is a function and returns instance', () => {
            expect(instance.decode).toBeTypeOf('function')
            expect(instance.decode(buffer)).toBe(instance)
        })

        it('should decode packet correctly', () => {
            instance.decode(buffer)

            expect(instance).toHaveProperty('nextHeader', 0x3B)
            expect(instance).toHaveProperty('headerLength', 16)
            expect(instance.payload).toBeInstanceOf(NoNext)
            expect(instance.payload).toHaveProperty('error', undefined)
        })
    })

    describe('#toString', () => {
        it('is a function', () => {
            expect(instance.toString).toBeTypeOf('function')
        })

        it('should return correct string representation', () => {
            instance.decode(Buffer.from('FF00000000000000', 'hex'))
            expect(instance.toString()).toBe('proto 255 undefined')

            instance.decode(Buffer.from(
                '0200000000000000'
                + '1600fa04effffffa', // IGMP
                'hex',
            ))
            expect(instance.toString()).toBe('IGMP Membership Report')
        })
    })
})
