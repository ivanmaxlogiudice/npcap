import { beforeEach, describe, expect, it } from 'bun:test'
import { Buffer } from 'node:buffer'
import { NullPacket } from '@/decode/packets'
import { IPv4, IPv6 } from '@/decode/protocols'

describe('NullPacket', () => {
    let instance: NullPacket

    beforeEach(() => {
        instance = new NullPacket()
    })

    describe('#decode', () => {
        it('is a function and returns the instance', () => {
            expect(NullPacket).toBeTypeOf('function')
            expect(instance).toBe(instance)
        })

        it('decode IPv4 packet', () => {
            instance.decode(Buffer.from(
                '00000002' // pftype
                + '46c000200000400001021274c0a82101effffffa94040000' // header
                + '1600fa04effffffa' // igmpv2
                + '00000000' // checksum
                , 'hex',
            ))

            expect(instance).toHaveProperty('pftype', 2)
            expect(instance.payload).toBeInstanceOf(IPv4)
        })

        it('decode IPv6 packet', () => {
            instance.decode(Buffer.from(
                '0000001E' // pftype
                + '60000000' // version=6, trafficClass=0x12, labelflow=0,
                + '0000' // payloadLength =0
                + 'ff' // a next header type which is not supported
                + '00' // hopLimit=0
                + 'fe80000000000000708dfe834114a512' // src address
                + '2001000041379e508000f12ab9c82815' // dest address
                + '1600fa04effffffa'
                , 'hex',
            ))

            expect(instance).toHaveProperty('pftype', 30)
            expect(instance.payload).toBeInstanceOf(IPv6)
        })
    })

    describe('#toString', () => {
        it('should return correct string representation', () => {
            // IPv4
            expect(
                instance.decode(
                    Buffer.from(
                        '00000002' // pftype
                        + '46c000200000400001021274c0a82101effffffa94040000' // header
                        + '1600fa04effffffa' // igmpv2
                        + '00000000' // checksum
                        , 'hex',
                    ),
                ).toString(),
            ).toBe('2 192.168.33.1 -> 239.255.255.250 flags [d] IGMP Membership Report')

            // IPv6
            expect(
                instance.decode(
                    Buffer.from(
                        '0000001E' // pftype
                        + '60000000' // version=6, trafficClass=0x12, labelflow=0,
                        + '0000' // payloadLength =0
                        + 'ff' // a next header type which is not supported
                        + '00' // hopLimit=0
                        + 'fe80000000000000708dfe834114a512' // src address
                        + '2001000041379e508000f12ab9c82815' // dest address
                        + '1600fa04effffffa'
                        , 'hex',
                    ),
                ).toString(),
            ).toBe('30 fe80:0000:0000:0000:708d:fe83:4114:a512 -> 2001:0000:4137:9e50:8000:f12a:b9c8:2815 proto 255 undefined')

            // Unkdown
            expect(
                instance.decode(Buffer.from('000000FF', 'hex')).toString(),
            ).toBe('255 undefined')
        })
    })
})
