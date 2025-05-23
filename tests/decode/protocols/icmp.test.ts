import { Buffer } from 'node:buffer'
import { ICMP } from '@/decode/protocols'
import { int8_to_hex } from '@/decode/utils'
import { describe, expect, it } from 'vitest'

describe('iCMP', () => {
    const buffer = Buffer.from('01020304', 'hex')
    let instance = new ICMP(buffer)

    describe('#constructor', () => {
        it('is a function and returns the instance', () => {
            expect(instance).toBeTypeOf('object')
            expect(instance).toBe(instance)
        })

        // it(`raises a ${ICMP.decoderName} event on decode`, () => {
        //     const handler = jest.fn()

        //     instance = new ICMP(buffer)

        //     expect(handler).toHaveBeenCalled()
        // })

        it('should decode ICMP packet correctly', () => {
            expect(instance).toHaveProperty('type', 1)
            expect(instance).toHaveProperty('code', 2)
            expect(instance).toHaveProperty('checksum', 772)
        })
    })

    describe('#toString', () => {
        const verifyToString = function verifyToString(type: number, code: number, result: string) {
            instance = new ICMP(Buffer.from(`${int8_to_hex[type] + int8_to_hex[code]}0000`, 'hex'), 0)

            expect(instance.toString()).toBe(result)
        }

        it('should return correct string representation', () => {
            verifyToString(0, 0, 'Echo Reply')

            verifyToString(3, 0, 'Destination Network Unreachable')
            verifyToString(3, 1, 'Destination Host Unreachable')
            verifyToString(3, 2, 'Destination Protocol Unreachable')
            verifyToString(3, 3, 'Destination Port Unreachable')
            verifyToString(3, 4, 'Fragmentation required, and DF flag set')
            verifyToString(3, 5, 'Source route failed')
            verifyToString(3, 6, 'Destination network unknown')
            verifyToString(3, 7, 'Destination host unknown')
            verifyToString(3, 8, 'Source host isolated')
            verifyToString(3, 9, 'Network administratively prohibited')
            verifyToString(3, 10, 'Host administratively prohibited')
            verifyToString(3, 11, 'Network unreachable for TOS')
            verifyToString(3, 12, 'Host unreachable for TOS')
            verifyToString(3, 13, 'Communication administratively prohibited')
            verifyToString(3, 14, 'Host Precedence Violation')
            verifyToString(3, 15, 'Precedence cutoff in effect')
            verifyToString(3, 16, 'Destination Unreachable (unknown code 16)')

            verifyToString(4, 0, 'Source Quench')

            verifyToString(5, 0, 'Redirect Network')
            verifyToString(5, 1, 'Redirect Host')
            verifyToString(5, 2, 'Redirect TOS and Network')
            verifyToString(5, 3, 'Redirect TOS and Host')
            verifyToString(5, 4, 'Redirect (unknown code 4)')

            verifyToString(6, 0, 'Alternate Host Address')

            verifyToString(7, 0, 'Reserved')

            verifyToString(8, 0, 'Echo Request')

            verifyToString(9, 0, 'Router Advertisement')

            verifyToString(10, 0, 'Router Solicitation')

            verifyToString(11, 0, 'TTL expired in transit')
            verifyToString(11, 1, 'Fragment reassembly time exceeded')
            verifyToString(11, 2, 'Time Exceeded (unknown code 2)')

            verifyToString(12, 0, 'Pointer indicates the error')

            verifyToString(15, 0, 'type 15 code 0')
        })
    })
})
