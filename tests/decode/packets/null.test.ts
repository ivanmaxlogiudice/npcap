import { describe, expect, it } from 'bun:test'
import { Buffer } from 'node:buffer'
import { NullPacket } from '@/decode/packets'
import { IPv4, IPv6 } from '@/decode/protocols'

describe('NullPacket', () => {
    let instance: NullPacket

    describe('#constructor', () => {
        it('is a function and returns the instance', () => {
            expect(NullPacket).toBeTypeOf('function')
            expect(instance).toBe(instance)
        })

        it('decode IPv4 packet', () => {
            instance = new NullPacket(Buffer.from(
                '00000002' // type = 2 (IPv4)
                + '46c000200000400001021274c0a82101effffffa94040000' // header
                + '1600fa04effffffa' // igmpv2
                + '00000000' // checksum
                , 'hex',
            ))

            expect(instance).toHaveProperty('type', 2)
            expect(instance.payload).toBeInstanceOf(IPv4)
        })

        it('decode IPv6 packet', () => {
            instance = new NullPacket(Buffer.from(
                '0000001E' // type = 30 (IPv6)
                + '61298765' // version=6, trafficClass=0x12, labelflow=0,
                + '0000' // payloadLength =0
                + '3b' // No next header
                + '00' // hopLimit=0
                + 'fe80000000000000708dfe834114a512' // src address
                + '2001000041379e508000f12ab9c82815' // dest address
                , 'hex',
            ))

            expect(instance).toHaveProperty('type', 30)
            expect(instance.payload).toBeInstanceOf(IPv6)
        })
    })

    describe('#toString', () => {
        it('should return correct string representation', () => {
            // IPv4
            expect(
                new NullPacket(
                    Buffer.from(
                        '00000002' // type
                        + '46c000200000400001021274c0a82101effffffa94040000' // header
                        + '1600fa04effffffa' // igmpv2
                        + '00000000' // checksum
                        , 'hex',
                    ),
                ).toString(),
            ).toBe('2 192.168.33.1 -> 239.255.255.250 flags [d] IGMP Membership Report')

            // IPv6
            expect(
                new NullPacket(
                    Buffer.from(
                        '0000001E' // type
                        + '61298765' // version=6, trafficClass=0x12, labelflow=0,
                        + '0000' // payloadLength =0
                        + '3b' // No next header
                        + '00' // hopLimit=0
                        + 'fe80000000000000708dfe834114a512' // src address
                        + '2001000041379e508000f12ab9c82815' // dest address
                        , 'hex',
                    ),
                ).toString(),
            ).toBe('30 fe80:0000:0000:0000:708d:fe83:4114:a512 -> 2001:0000:4137:9e50:8000:f12a:b9c8:2815 NoNext ')
        })
    })
})
