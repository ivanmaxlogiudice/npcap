import { createRequire } from 'node:module'
import type { Buffer } from 'node:buffer'
import type { CaptureStats, Device, LinkType } from './types'

const require = createRequire(import.meta.url)
const addon = require('../build/Release/npcap.node')

export interface Session {
    /**
     * Opens a live connection for capturing network packets.
     *
     * @param {string} device - The name of the network interface to capture packets from.
     * @param {() => void} onPacket - A callback function to handle captured packets.
     * @param {string} filter - A filter expression for capturing specific packets.
     * @param {number} bufferSize - The size of the buffer for capturing packets.
     * @param {Buffer} header - The buffer for storing the header of captured packets.
     * @param {Buffer} buffer - The buffer for storing captured packets.
     * @param {number} snapLen - The maximum number of bytes to capture per packet.
     * @param {string} outFile - The file path to write captured packets to.
     * @param {boolean} monitor - Whether to capture in monitor mode.
     * @param {number} timeout - The timeout duration for capturing packets.
     * @param {(message: string) => void} warningHandler - A callback function to handle warnings.
     * @param {boolean} promiscuous - Whether to set promiscuous mode for capturing packets.
     * @param {number} minBytes - The minimum number of bytes to capture (Only in Windows).
     *
     * @returns {LinkType} The type of the link.
     */
    openLive: (
        device: string,
        onPacket: () => void,
        filter: string,
        bufferSize: number,
        header: Buffer,
        buffer: Buffer,
        snapLen: number,
        outFile: string,
        monitor: boolean,
        timeout: number,
        warningHandler: (message: string) => void,
        promiscuous: boolean,
        minBytes: number
    ) => LinkType

    /**
     * Opens an offline connection for processing captured network packets from a pcap file.
     *
     * @param {string} device - The path to the pcap file.
     * @param {() => void} onPacket - A callback function to handle packets.
     * @param {string} filter - A filter expression for capturing specific packets.
     * @param {number} bufferSize - The size of the buffer for processing packets.
     * @param {Buffer} header - The header buffer.
     * @param {Buffer} buffer - The buffer for storing captured packets.
     * @param {number} snapLen - The maximum number of bytes to capture per packet.
     * @param {string} outFile - The file path to write captured packets to.
     * @param {boolean} monitor - Whether to capture in monitor mode.
     * @param {number} timeout - The timeout duration for capturing packets.
     * @param {(message: string) => void} warningHandler - A callback function to handle warnings.
     * @param {boolean} promiscuous - Whether to set promiscuous mode for capturing packets.
     * @param {number} minBytes - The minimum number of bytes to capture (Only in Windows).
     *
     * @returns {LinkType} The type of the link.
     */
    openOffline: (
        device: string,
        onPacket: () => void,
        filter: string,
        bufferSize: number,
        header: Buffer,
        buffer: Buffer,
        snapLen: number,
        outFile: string,
        monitor: boolean,
        timeout: number,
        warningHandler: (message: string) => void,
        promiscuous: boolean,
        minBytes: number
    ) => LinkType

    /**
     * Get the current capture statistics.
     *
     * The statistics do not behave the same way on all platforms.
     *
     * `ps_recv` might count packets whether they passed the filter or not,
     * or it might count only packets that pass the filter. It also might,
     * or might not, count packets dropped because there was no room in the
     * operating system's buffer when they arrived.
     *
     * `ps_drop` is not available on all platforms; it is zero on platforms
     * where it's not available. If packet filtering is done in libpcap,
     * rather than in the operating system, it would count packets that
     * don't pass the filter.
     *
     * Both `ps_recv` and `ps_drop` might, or might not,
     * count packets not yet read from the operating system and thus not
     * yet seen by the application.
     *
     * `ps_ifdrop` might, or might not, be implemented;
     * if it's zero, that might mean that no packets were dropped
     * by the interface, or it might mean that the statistic is unavailable,
     * so it should not be treated as an indication that the interface
     * did not drop any packets.
     *
     * @throws {Error} If failed to get stats.
     */
    stats: () => CaptureStats

    /**
     * Injects data into the network interface.
     *
     * @param {Buffer} data - The data to be injected into the network interface.
     *
     * @returns {boolean} Returns true if the injection is successful.
     * @throws {Error} If injection fails.
     */
    inject: (data: Buffer) => boolean

    /**
     * Close the capture session.
     *
     * No more `packet` events will be emitted.
     */
    close: () => void
}

export interface SessionClass {
    (): Session // Invoke as plain function
    new(): Session // Invoke as constructor
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

    /**
     * Retrieves the default device.
     *
     * @returns The name of the default device.
     *
     * @throws {Error} If there is an error retrieving the default device.
     */
    defaultDevice: () => string | undefined

    /**
     * This expose the addon Session class.
     *
     * Use `createSession` and `createOfflineSession` instead.
     */
    Session: SessionClass
}

export const npcap: Npcap = addon
