import { describe, expect, it } from 'vitest'
import { int8_to_dec, int8_to_hex, int8_to_hex_nopad } from '@/decode/utils'

describe('util', () => {
    describe('int8_to_hex', () => {
        it('is an array where uint8 values are the indices', () => {
            expect(int8_to_hex).toHaveLength(256)
        })

        it('maps uint8 values to hex strings e.g. [0]=="00"', () => {
            expect(int8_to_hex[0]).toBe('00')
            expect(int8_to_hex[1]).toBe('01')
            expect(int8_to_hex[255]).toBe('ff')
        })
    })

    describe('int8_to_dec', () => {
        it('is an array where uint8 values are the indices', () => {
            expect(int8_to_dec).toHaveLength(256)
        })

        it('maps uint8 values to decimal strings e.g. [0]=="0"', () => {
            expect(int8_to_dec[0]).toBe('0')
            expect(int8_to_dec[1]).toBe('1')
            expect(int8_to_dec[255]).toBe('255')
        })
    })

    describe('int8_to_hex_nopad', () => {
        it('is an array where uint8 values are the indices', () => {
            expect(int8_to_hex_nopad).toHaveLength(256)
        })

        it('maps uint8 values to hex strings without the leading 0 e.g. [0]=="0"', () => {
            expect(int8_to_hex_nopad[0]).toBe('0')
            expect(int8_to_hex_nopad[1]).toBe('1')
            expect(int8_to_hex_nopad[255]).toBe('ff')
        })
    })
})
