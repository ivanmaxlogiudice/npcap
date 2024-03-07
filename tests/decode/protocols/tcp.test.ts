import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { Tcp } from '@/decode/protocols'

describe('tcp', () => {
    const buffer = Buffer.from('b5dd00500aaf604e0000000060c2102044b2000002040218', 'hex')
    let instance = new Tcp(buffer)

    describe('#constructor', () => {
        it('is a function', () => {
            expect(instance).toBeTypeOf('object')
        })

        it('returns the instance', () => {
            expect(instance).toBe(instance)
        })

        // it(`raises a ${Tcp.decoderName} event on decode`, () => {
        //     const handler = jest.fn()

        //     emitter.on(Tcp.decoderName, handler)
        //     instance.decode(buffer)

        //     expect(handler).toHaveBeenCalled()
        // })

        it('should decode TCP packet correctly', () => {
            expect(instance).toHaveProperty('sport', 46557)
            expect(instance).toHaveProperty('dport', 80)
            expect(instance).toHaveProperty('seqno', 179265614)
            expect(instance).toHaveProperty('headerLength', 24)

            expect(instance).toHaveProperty('flags.nonce', false)

            // Congestion Window Reduce
            expect(instance).toHaveProperty('flags.cwr', true)

            // Enc-echo set
            expect(instance).toHaveProperty('flags.ece', true)

            // Urgent
            expect(instance).toHaveProperty('flags.urg', false)

            // Acknowledgement
            expect(instance).toHaveProperty('flags.ack', false)

            // Push
            expect(instance).toHaveProperty('flags.psh', false)

            // Reset
            expect(instance).toHaveProperty('flags.rst', false)
            expect(instance).toHaveProperty('flags.syn', true)
            expect(instance).toHaveProperty('flags.fin', false)

            expect(instance).toHaveProperty('windowSize', 4128)
            expect(instance).toHaveProperty('checksum', 17586)
            expect(instance).toHaveProperty('urgentPointer', 0)

            instance = new Tcp(buffer, 0, 24)
            expect(instance).toHaveProperty('dataLength', 0)
            expect(instance).toHaveProperty('data', null)
        })
    })

    describe('#toString', () => {
        it('is a function', () => {
            expect(instance.toString).toBeTypeOf('function')
        })

        it('returns a value like #->80 seq 179265614 ack 0 flags [ces] win 4128 csum 17586 [mss:536] len 0', () => {
            expect(new Tcp(buffer, 0, 24).toString()).toBe('46557 -> 80 seq 179265614 ack 0 flags [ces] win 4128 csum 17586 [mss:536] len 0')
        })
    })
})
