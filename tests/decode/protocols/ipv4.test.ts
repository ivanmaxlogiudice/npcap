import { beforeEach, describe, expect, it, jest } from 'bun:test'
import { Buffer } from 'node:buffer'
import EventEmitter from 'node:events'
import { IPFlags, IPv4, IPv4Addr } from '../../../lib/decode/protocols/ipv4'

describe('IPFlags', () => {
    let ipFlags: IPFlags

    beforeEach(() => {
        ipFlags = new IPFlags()
    })

    it('should decode flags correctly', () => {
        ipFlags.decode(0b10000000) // Setting the reserved flag
        expect(ipFlags.reserved).toBe(true)
        expect(ipFlags.doNotFragment).toBe(false)
        expect(ipFlags.moreFragments).toBe(false)

        ipFlags.decode(0b01000000) // Setting the doNotFragment flag
        expect(ipFlags.reserved).toBe(false)
        expect(ipFlags.doNotFragment).toBe(true)
        expect(ipFlags.moreFragments).toBe(false)

        ipFlags.decode(0b00100000) // Setting the moreFragments flag
        expect(ipFlags.reserved).toBe(false)
        expect(ipFlags.doNotFragment).toBe(false)
        expect(ipFlags.moreFragments).toBe(true)
    })

    it('should return correct string representation', () => {
        ipFlags.reserved = true
        ipFlags.doNotFragment = true
        ipFlags.moreFragments = false
        expect(ipFlags.toString()).toBe('[rd]')

        ipFlags.reserved = false
        ipFlags.doNotFragment = false
        ipFlags.moreFragments = true
        expect(ipFlags.toString()).toBe('[m]')

        ipFlags.reserved = false
        ipFlags.doNotFragment = false
        ipFlags.moreFragments = false
        expect(ipFlags.toString()).toBe('[]')
    })
})

describe('IPv4Addr', () => {
    let instance: IPv4Addr
    let buffer: Buffer

    beforeEach(() => {
        instance = new IPv4Addr()
        buffer = Buffer.from([192, 168, 1, 1])
    })

    describe('#decode', () => {
        it('is a function', () => {
            expect(instance.decode).toBeTypeOf('function')
        })

        it('should decode address correctly', () => {
            expect(instance.decode(buffer, 0)).toHaveProperty('addr', [192, 168, 1, 1])
        })
    })

    describe('#toString()', () => {
        it('is a function', () => {
            expect(instance.toString).toBeTypeOf('function')
        })

        it('should return correct string representation', () => {
            expect(instance.decode(buffer, 0).toString()).toBe('192.168.1.1')

            instance.addr = [192, 168, 1, 1]
            expect(instance.toString()).toBe('192.168.1.1')

            instance.addr = [0, 0, 0, 0]
            expect(instance.toString()).toBe('0.0.0.0')

            instance.addr = [255, 255, 255, 255]
            expect(instance.toString()).toBe('255.255.255.255')
        })
    })
})

describe('IPv4', () => {
    let emitter: EventEmitter
    let instance: IPv4
    let buffer: Buffer

    beforeEach(() => {
        emitter = new EventEmitter()
        instance = new IPv4(emitter)
        buffer = Buffer.from(
            '46c000200000400001021274c0a82101effffffa94040000' // header
            + '1600fa04effffffa' // igmpv2
            + '00000000', // checksum
            'hex',
        )
    })

    describe('#decode', () => {
        it('is a function and returns the instance', () => {
            expect(instance.decode).toBeTypeOf('function')
            expect(instance.decode(buffer, 0)).toBe(instance)
        })

        it(`raises a ${IPv4.name} event on decode`, () => {
            const handler = jest.fn()

            emitter.on(instance.decoderName, handler)
            instance.decode(buffer, 0)

            expect(handler).toHaveBeenCalled()
        })

        it('should decode IPv4 packet correctly', () => {
            instance.decode(buffer, 0)

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

        it('returns a value like "192.168.33.1 -> 239.255.255.250 IGMP Membership Report" when no flags are set', () => {
            const noflags = Buffer.from(
                '46c000200000000001021274c0a82101effffffa94040000' // header
                + '1600fa04effffffa' // igmpv2
                + '00000000', // checksum
                'hex',
            )

            expect(instance.decode(noflags).toString()).toBe('192.168.33.1 -> 239.255.255.250 IGMP Membership Report')
        })
    })
})
