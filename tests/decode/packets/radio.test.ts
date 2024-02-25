import { beforeEach, describe, expect, it, jest } from 'bun:test'
import { Buffer } from 'node:buffer'
import EventEmitter from 'node:events'
import { RadioPacket } from '../../../lib/decode/packets/radio'

describe('RadioPacket', () => {
    let emitter: EventEmitter
    let instance: RadioPacket

    // a probe that has no additional information in the header
    const buffer1 = Buffer.from('000012002e48000000028509a000d3010000' // Example of a radio tap header
        + '40000000ffffffffffffe4ce8f16da48ffffffffffff804b' // Probe request
        + '0000010402040b16' // i802.11 tags [ssid]
        + 'FFFFFFFF', 'hex') // checksum, note this one is not valid

    // a probe that has additional information in the header
    const buffer2 = Buffer.from('00001A002F480000000000000000000010026C09A000D8000000' // Example of a radio tap header
        + '40000000ffffffffffffe4ce8f16da48ffffffffffff804b' // Probe request
        + '0000010402040b16' // i802.11 tags [ssid]
        + 'FFFFFFFF', 'hex') // checksum, note this one is not valid

    const buffer3 = Buffer.from('000018006f0000008e64643a0000000010029409a000af00' // Example of a radio tap header
        + '40000000ffffffffffffe4ce8f16da48ffffffffffff804b' // Probe request
        + '0000010402040b16' // i802.11 tags [ssid]
        + 'FFFFFFFF', 'hex') // checksum, note this one is not valid

    beforeEach(() => {
        emitter = new EventEmitter()
        instance = new RadioPacket(emitter)
    })

    describe('#decode', () => {
        it('is a function and returns the instance', () => {
            expect(RadioPacket).toBeTypeOf('function')
            expect(instance).toBe(instance)
        })

        it(`raises a ${RadioPacket.decoderName} event on decode`, () => {
            const handler = jest.fn()

            emitter.on(RadioPacket.decoderName, handler)
            instance.decode(buffer1)

            expect(handler).toHaveBeenCalled()
        })

        it('decode radio packet', () => {
            instance.decode(buffer1)

            expect(instance).toHaveProperty('headerLength', 18)
            expect(instance).toHaveProperty('headerPad', 0)
            expect(instance).toHaveProperty('headerLength', 18)
            expect(instance).toHaveProperty('presentFields', 18478)

            // TODO: Handles 64-bit fields
            instance.decode(buffer3)
        })
    })
})
