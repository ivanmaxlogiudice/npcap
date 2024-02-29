import type { Buffer } from 'node:buffer'

/**
 * Format of the link-type headers.
 *
 * @see {@link https://www.tcpdump.org/linktypes.html | LinkType Headers}
 */
export type LinkType =
    | 'LINKTYPE_ETHERNET'
    | 'LINKTYPE_NULL'
    | 'LINKTYPE_RAW'
    | 'LINKTYPE_LINUX_SLL'
    // | 'LINKTYPE_IEEE802_11_RADIO'

export interface CaptureStats {
    /**
     * Number of packets received.
     */
    ps_recv: number

    /**
     * Number of packets dropped by the network interface or its driver.
     */
    ps_ifdrop: number

    /**
     * Number of packets dropped because there was no room in the operating
     * system's buffer when they arrived, because packets weren't being read fast enough.
     */
    ps_drop: number
}

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

export interface PacketData<T = LinkType> {
    linkType: T
    buffer: Buffer
    header: Buffer
}

export interface CommonSessionOptions {
    /**
     * Specifies the filter criteria for capturing packets.
     *
     * If not provided, all packets visible on the interface will be captured by default.
     *
     * @see {@link https://npcap.com/guide/wpcap/pcap-filter.html | Npcap Filters Documentation}
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
export const ETHERNET_TYPE_ARP = 0x806
export const ETHERNET_TYPE_VLAN = 0x8100
export const ETHERNET_TYPE_IPV6 = 0x86dd

export const EthernetTypeString: Record<number, string> = {
    [ETHERNET_TYPE_IPV4]: 'IPv4',
    [ETHERNET_TYPE_ARP]: 'Arp',
    [ETHERNET_TYPE_IPV6]: 'IPv6',
}
