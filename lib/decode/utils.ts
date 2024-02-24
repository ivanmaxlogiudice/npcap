const int8_to_hex: string[] = []
const int8_to_hex_nopad: string[] = []
const int8_to_dec: string[] = []

for (let i = 0; i <= 255; i++) {
    int8_to_hex[i] = i.toString(16).padStart(2, '0')
    int8_to_hex_nopad[i] = i.toString(16)
    int8_to_dec[i] = i.toString()
}

export { int8_to_dec, int8_to_hex, int8_to_hex_nopad }
