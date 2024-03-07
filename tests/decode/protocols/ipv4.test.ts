import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { IPFlags, IPv4, IPv4Addr } from '@/decode/protocols'

describe('iPFlags', () => {
    let instance: IPFlags

    it('should decode flags correctly', () => {
        instance = new IPFlags(0b10000000) // Setting the reserved flag
        expect(instance.reserved).toBe(true)
        expect(instance.doNotFragment).toBe(false)
        expect(instance.moreFragments).toBe(false)

        instance = new IPFlags(0b01000000) // Setting the doNotFragment flag
        expect(instance.reserved).toBe(false)
        expect(instance.doNotFragment).toBe(true)
        expect(instance.moreFragments).toBe(false)

        instance = new IPFlags(0b00100000) // Setting the moreFragments flag
        expect(instance.reserved).toBe(false)
        expect(instance.doNotFragment).toBe(false)
        expect(instance.moreFragments).toBe(true)
    })

    it('should return correct string representation', () => {
        instance.reserved = true
        instance.doNotFragment = true
        instance.moreFragments = false
        expect(instance.toString()).toBe('[rd]')

        instance.reserved = false
        instance.doNotFragment = false
        instance.moreFragments = true
        expect(instance.toString()).toBe('[m]')

        instance.reserved = false
        instance.doNotFragment = false
        instance.moreFragments = false
        expect(instance.toString()).toBe('[]')
    })
})

describe('iPv4Addr', () => {
    const buffer = Buffer.from([192, 168, 1, 1])
    const instance = new IPv4Addr(buffer)

    describe('#constructor', () => {
        it('is a function', () => {
            expect(instance).toBeTypeOf('object')
        })

        it('should decode address correctly', () => {
            expect(instance).toHaveProperty('addr', [192, 168, 1, 1])
        })
    })

    describe('#toString()', () => {
        it('is a function', () => {
            expect(instance.toString).toBeTypeOf('function')
        })

        it('should return correct string representation', () => {
            expect(instance.toString()).toBe('192.168.1.1')

            instance.addr = [192, 168, 1, 1]
            expect(instance.toString()).toBe('192.168.1.1')

            instance.addr = [0, 0, 0, 0]
            expect(instance.toString()).toBe('0.0.0.0')

            instance.addr = [255, 255, 255, 255]
            expect(instance.toString()).toBe('255.255.255.255')
        })
    })
})

describe('iPv4', () => {
    const buffer = Buffer.from(
        '46c000200000400001021274c0a82101effffffa94040000' // header
        + '1600fa04effffffa' // igmpv2
        + '00000000', // checksum
        'hex',
    )

    const instance = new IPv4(buffer)

    describe('#constructor', () => {
        it('is a function and returns the instance', () => {
            expect(instance).toBeTypeOf('object')
            expect(instance).toBe(instance)
        })

        // it(`raises a ${IPv4.decoderName} event on decode`, () => {
        //     const handler = jest.fn()

        //     emitter.on(IPv4.decoderName, handler)
        //     instance.decode(buffer)

        //     expect(handler).toHaveBeenCalled()
        // })

        it('should decode IPv4 packet correctly', () => {
            expect(instance).toHaveProperty('version', 4)
            expect(instance).toHaveProperty('headerLength', 24)
            expect(instance).toHaveProperty('diffserv', 0xc0)

            expect(instance.flags?.reserved).toBe(false)
            expect(instance.flags?.doNotFragment).toBe(true)
            expect(instance.flags?.moreFragments).toBe(false)

            expect(instance).toHaveProperty('fragmentOffset', 0)
            expect(instance).toHaveProperty('ttl', 1)
            expect(instance).toHaveProperty('protocol', 2)
            expect(instance).toHaveProperty('headerChecksum', 0x1274)
            expect(instance).toHaveProperty('saddr.addr', [192, 168, 33, 1])
            expect(instance).toHaveProperty('daddr.addr', [239, 255, 255, 250])
        })
    })

    describe('#toString', () => {
        it('is a function', () => {
            expect(instance.toString).toBeTypeOf('function')
        })

        it('should return correct string representation', () => {
            const noflags = Buffer.from(
                '46c000200000000001021274c0a82101effffffa94040000' // header
                + '1600fa04effffffa' // igmpv2
                + '00000000', // checksum
                'hex',
            )

            expect(new IPv4(noflags).toString()).toBe('192.168.33.1 -> 239.255.255.250 IGMP Membership Report')
        })
    })
})
