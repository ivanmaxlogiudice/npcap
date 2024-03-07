import { describe, expect, it } from 'vitest'
import { SLLPacket } from '@/decode/packets'

describe('sLLPacket', () => {
    let instance: SLLPacket

    // TODO: Add missing test
    describe('#constructor', () => {
        it('is a function and returns the instance', () => {
            expect(SLLPacket).toBeTypeOf('function')
            expect(instance).toBe(instance)
        })

        it('decode IPv4 packet', () => {

        })

        it('decode IPv6 packet', () => {

        })
    })

    describe('#toString', () => {
        it('should return correct string representation', () => {

        })
    })
})
