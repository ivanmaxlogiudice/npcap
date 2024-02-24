import type { Buffer } from 'node:buffer'

export type LinkType =
    | 'NULL'
    | 'ETHERNET'
    | 'IEEE802_11_RADIO'
    | 'RAW'
    | 'LINUX_SLL'

export interface Address {
    addr: string
    netmask: string
    broadaddr?: string
    dstaddr?: string
}

export interface Device {
    name: string
    description?: string
    addresses: Address[]
    loopback?: boolean
}

export interface PacketData {
    buffer: Buffer
    header: Buffer
    linkType: LinkType
}

export interface CommonSessionOptions {
    /**
     * Specifies the filter criteria for capturing packets.
     *
     * If not provided, all packets visible on the interface will be captured by default.
     *
     * @see {@link https://npcap.com/guide/wpcap/pcap-filter.html|Npcap Filters Documentation}
     */
    filter?: string
}

export interface LiveSessionOptions extends CommonSessionOptions {
    /**
     * Size of the ring buffer where packets are stored until delivered to your code, in bytes.
     *
     * @default 10485760 (10MB)
     */
    bufferSize?: number

    /**
     * Maximum number of bytes to capture from each packet during a session.
     *
     * @default 65535
     */
    snapLen?: number

    /**
     * File path where captured packets will be saved.
     *
     * Example: '/path/to/save/packets.pcap'
     */
    outFile?: string

    /**
     * Enables monitor mode.
     *
     * @default false
     */
    monitor?: boolean

    /**
     * Packets buffer timeout in ms.
     *
     * @default 1000
     */
    timeout?: number

    /**
     * Function that is called whenever Npcap emits a warning.
     *
     * For example when an interface has no addresses.
     *
     * @param message The warning that npcap will provide.
     */
    warningHandler?: (message: string) => void

    /**
     * Set the promiscuous mode.
     *
     * @default true
     */
    promiscuous?: boolean
}

export interface OfflineSessionOptions extends CommonSessionOptions {

}

export const ETHERNET_TYPE_IPV4 = 0x800
export const ETHERNET_TYPE_VLAN = 0x8100
