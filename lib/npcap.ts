import { createRequire } from 'node:module'
import type { Device, LinkType } from './types'
import type { Buffer } from 'node:buffer'

const require = createRequire(import.meta.url)
const addon = require('../build/Release/npcap.node')

export interface Session {
    openLive: (
        device: string,
        onPacket: (copyLen: number, truncated: boolean) => void,
        filter: string,
        bufferSize: number,
        header: Buffer,
        buffer: Buffer,
        snapLen: number,
        outFile: string,
        monitor: boolean,
        timeout: number,
        warningHandler: (message: string) => void,
        promiscuous: boolean
    ) => LinkType

    openOffline: (
        device: string,
        onPacket: (copyLen: number, truncated: boolean) => void,
        filter: string,
        bufferSize: number,
        header: Buffer,
        buffer: Buffer,
        snapLen: number,
        outFile: string,
        monitor: boolean,
        timeout: number,
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
