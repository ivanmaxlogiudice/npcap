import { beforeEach, describe, expect, it } from 'bun:test'
import { Buffer } from 'node:buffer'
import EventEmitter from 'node:events'
import { EthernetAddr, EthernetPacket } from '@/decode/packets'
import { IPv4 } from '@/decode/protocols'
import { ETHERNET_TYPE_IPV4 } from '@/types'

describe('EthernetAddr', () => {
    let instance: EthernetAddr

    beforeEach(() => {
        instance = new EthernetAddr(Buffer.from('010203040506', 'hex'))
    })

    describe('constructor', () => {
        it('is a function and returns the instance', () => {
            expect(EthernetAddr).toBeTypeOf('function')
            expect(instance).toBe(instance)
        })

        it('decodes ethernet (MAC) address', () => {
            expect(instance).toHaveProperty('addr', [1, 2, 3, 4, 5, 6])
        })
    })

    describe('#toString', () => {
        it('is a function', () => {
            expect(instance.toString).toBeTypeOf('function')
        })

        it('should return correct string representation', () => {
            expect(instance.toString()).toBe('01:02:03:04:05:06')
        })
    })
})

describe('EthernetPacket', () => {
    let emitter: EventEmitter
    let instance: EthernetPacket
    const bufferIPv4WithoutVLAN = Buffer.from(
        'e8ada60b3fd4' // dhost
        + '4c3488b4b2ac' // shost
        + '0800' // Ethertype (IPv4)
        + '45000028ebbf4000800699a7c0a8000663b55105c3e001bb717cb4566238f71f5010fee2f6c10000',
        'hex',
    )
    const bufferIPv4WithVLAN = Buffer.from(
        'AABBCCDDEEFF112233445566810000010800'
        + '46c000200000400001021274c0a82101effffffa94040000' // header
        + '1600fa04effffffa' // igmpv2
        + '00000000',
        'hex',
    )

    beforeEach(() => {
        emitter = new EventEmitter()
        instance = new EthernetPacket(emitter)
    })

    describe('#decode', () => {
        it('should decode IPv4 without VLAN', () => {
            instance.decode(bufferIPv4WithoutVLAN)

            expect(instance).toHaveProperty('dhost.addr', [232, 173, 166, 11, 63, 212])
            expect(instance).toHaveProperty('shost.addr', [76, 52, 136, 180, 178, 172])
            expect(instance).toHaveProperty('ethertype', ETHERNET_TYPE_IPV4)
            expect(instance).toHaveProperty('vlan', undefined)

            expect(instance.payload).toBeInstanceOf(IPv4)
        })

        it('should decode IPv4 with VLAN', () => {
            instance.decode(bufferIPv4WithVLAN)

            expect(instance).toHaveProperty('dhost.addr', [170, 187, 204, 221, 238, 255])
            expect(instance).toHaveProperty('shost.addr', [17, 34, 51, 68, 85, 102])
            expect(instance).toHaveProperty('ethertype', ETHERNET_TYPE_IPV4)
            expect(instance.vlan?.toString()).toBe('0 0 1')

            expect(instance.payload).toBeInstanceOf(IPv4)
        })

        // TODO: Test IPv6
    })

    describe('#toString', () => {
        it('should return IPv4 string representation without VLAN', () => {
            instance.decode(bufferIPv4WithoutVLAN)

            expect(instance.toString()).toBe('4c:34:88:b4:b2:ac -> e8:ad:a6:0b:3f:d4 IPv4 192.168.0.6 -> 99.181.81.5 flags [d] Tcp 50144 -> 443 seq 1903998038 ack 1647900447 flags [a] win 65250 csum 63169 [.] len 0')
        })

        it('should return IPv6 string representation with VLAN', () => {
            instance.decode(bufferIPv4WithVLAN)

            expect(instance.toString()).toBe('11:22:33:44:55:66 -> aa:bb:cc:dd:ee:ff vlan 0 0 1 IPv4 192.168.33.1 -> 239.255.255.250 flags [d] IGMP Membership Report')
        })
    })
})
