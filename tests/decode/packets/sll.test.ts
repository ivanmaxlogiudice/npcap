import { beforeEach, describe, expect, it } from 'bun:test'
import { SLLPacket } from '@/decode/packets'

describe('SLLPacket', () => {
    let instance: SLLPacket

    beforeEach(() => {
        instance = new SLLPacket()
    })

    // TODO: Add missing test
    describe('#decode', () => {
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
