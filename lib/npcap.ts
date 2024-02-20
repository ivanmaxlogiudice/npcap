import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const addon = require('../build/Release/npcap.node')

export type LinkType =
    | 'LINKTYPE_NULL'
    | 'LINKTYPE_ETHERNET'
    | 'LINKTYPE_IEEE802_11_RADIO'
    | 'LINKTYPE_RAW'
    | 'LINKTYPE_LINUX_SLL'

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

export interface Session {
    openLive: (
        device: string,
        filter: string,
        bufferSize: number,
        snapLength: number,
        outFile: string,
        onPacketReady: () => void,
        monitor: boolean,
        bufferTimeout: number,
        warningHandler: (message: string) => void,
        promiscuous: boolean
    ) => LinkType,

    openOffline: (
        device: string,
        filter: string,
        bufferSize: number,
        snapLength: number,
        outFile: string,
        onPacketReady: () => void,
        monitor: boolean,
        bufferTimeout: number,
        warningHandler: (message: string) => void,
        promiscuous: boolean
    ) => LinkType

    /**
     * 
     * @param buffer 
     * @param header 
     * 
     * @returns The amount of packets read.
     */
    dispatch: (buffer: Buffer, header: Buffer) => number

    close: () => void

    /**
     * This function is declared in the JS side.
     */
    readCallback: () => void
}

export interface SessionClass {
    new(): Session
}

export interface Npcap {
    /**
     * Retrieves the version of the Npcap library.
     *
     * @returns The Npcap library version, or undefined if unavailable.
     */
    libVersion: () => string | undefined

    /**
     * Retrieves a list of network devices available on the system.
     *
     * @returns An array of available network devices.
     *
     * @throws {Error} If there is an error retrieving the list of devices.
     */
    deviceList: () => Device[]

    /**
     * Searches for a network device with the specified IP address.
     *
     * @param ip The IP address to search for.
     *
     * @returns The name of the network device associated with the
     * specified IP address, or undefined if the device is not found.
     *
     * @throws {Error} If there is an error searching for the device.
     */
    findDevice: (ip: string) => string | undefined

    Session: SessionClass
}

export const npcap: Npcap = addon
