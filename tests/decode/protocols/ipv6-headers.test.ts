import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { HeaderExtension, NoNext } from '@/decode/protocols'

describe('noNext', () => {
    const buffer = Buffer.from('', 'hex')
    const instance = new NoNext(buffer)

    describe('#constructor', () => {
        it('is a function and returns instance', () => {
            expect(instance).toBeTypeOf('object')
            expect(instance).toBe(instance)
        })

        it('throw an error', () => {
            expect(() => new NoNext(Buffer.from('00', 'hex'))).toThrow('There is more packet left to be parse, but NoNext.decode was called with 1 bytes left.')
        })
    })

    describe('#toString', () => {
        it('is a function', () => {
            expect(instance.toString).toBeTypeOf('function')
        })

        it('returns ""', () => {
            expect(instance.toString()).toBe('')
        })
    })
})

describe('headerExtension', () => {
    const buffer = Buffer.from(
        '3B' // No next will be the next header
        + '01' // the length of the the header in 8 byte units - 8bytes
        + '0000000000000000'
        + '000000000000', // details about the current header
        'hex',
    )
    let instance = new HeaderExtension(buffer)

    describe('#constructor', () => {
        it('is a function and returns instance', () => {
            expect(instance).toBeTypeOf('object')
            expect(instance).toBe(instance)
        })

        it('should decode packet correctly', () => {
            expect(instance).toHaveProperty('nextHeader', 0x3B)
            expect(instance).toHaveProperty('headerLength', 16)
            expect(instance.payload).toBeInstanceOf(NoNext)
        })
    })

    describe('#toString', () => {
        it('is a function', () => {
            expect(instance.toString).toBeTypeOf('function')
        })

        it('should return correct string representation', () => {
            instance = new HeaderExtension(Buffer.from(
                '0200000000000000'
                + '1600fa04effffffa', // IGMP
                'hex',
            ))
            expect(instance.toString()).toBe('IGMP Membership Report')
        })
    })
})
