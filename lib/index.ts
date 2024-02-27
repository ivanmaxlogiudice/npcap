import { Buffer } from 'node:buffer'
import type { Session } from './npcap'
import type { LinkType, LiveSessionOptions, OfflineSessionOptions, PacketData } from './types'
import { decode } from './decode'
import { TypedEventEmitter } from './emitter'
import { npcap } from './npcap'

export class NpcapSession extends TypedEventEmitter<{
    packet: [packet: PacketData]
}> {
    device: string

    /** Raw packets bytes */
    buffer: Buffer

    /** Encoded information about the packet (timestamp, size) */
    header: Buffer
    linkType: LinkType

    session: Session

    constructor(live: boolean, device?: string, options: LiveSessionOptions = {}) {
        super()

        const {
            filter = '',
            bufferSize = 10485760,
            snapLen = 65535,
            outFile = '',
            monitor = false,
            timeout = 1000,
            warningHandler = this.warningHandler,
            promiscuous = true,
        } = options

        this.device = device || npcap.defaultDevice() || ''
        this.buffer = Buffer.alloc(snapLen)
        this.header = Buffer.alloc(16)

        const onPacket = this.#onPacket.bind(this)

        this.session = new npcap.Session()

        if (live) {
            this.linkType = this.session.openLive(
                this.device,
                onPacket,
                filter,
                bufferSize,
                this.header,
                this.buffer,
                snapLen,
                outFile,
                monitor,
                timeout,
                warningHandler,
                promiscuous,
            )
        }
        else {
            this.linkType = this.session.openOffline(
                this.device,
                onPacket,
                filter,
                bufferSize,
                this.header,
                this.buffer,
                snapLen,
                outFile,
                monitor,
                timeout,
                warningHandler,
                promiscuous,
            )
        }
    }

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
    stats() {
        return this.session.stats()
    }

    /**
     * Injects data into the network interface.
     *
     * @param {Buffer} data - The data to be injected into the network interface.
     *
     * @returns {boolean} Returns true if the injection is successful.
     * @throws {Error} If injection fails.
     */
    inject(data: Buffer) {
        return this.session.inject(data)
    }

    /**
     * Close the capture session.
     *
     * No more `packet` events will be emitted.
     */
    close() {
        this.removeAllListeners()
        this.session.close()
    }

    /**
     * A callback function to handle Npcap warnings.
     *
     * This function can be overriden.
     *
     * @param message The warning that npcap will provide.
     *
     * @example
     *
     * session.warningHandler = (message: string) => {
     *     console.log(`[Overrided warningHandler] ${message}`)
     * }
     */
    warningHandler(message: string) {
        console.log(`[warningHandler] ${message}`)
    }

    #onPacket() {
        this.emit('packet', {
            buffer: this.buffer,
            header: this.header,
            linkType: this.linkType,
        })
    }
}

/**
 * Create a live capture session on the specified device
 * and starts capturing packets.
 *
 * @param device The name of the interface to capture packets.
 * @param options Capture options.
 */
export function createSession(device: string, options: LiveSessionOptions = {}) {
    return new NpcapSession(true, device, options)
}

/**
 * Starts an 'offline' capture session that emits packets,
 * read from a capture file.
 *
 * @param path File path to the `.pcap` file to read.
 * @param options Capture options.
 */
export function createOfflineSession(path: string, options: OfflineSessionOptions = {}) {
    return new NpcapSession(false, path, options)
}

export { decode, npcap }
