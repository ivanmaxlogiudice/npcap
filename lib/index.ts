import { Buffer } from 'node:buffer'
import type { Session } from './npcap'
import type { LinkType, LiveSessionOptions, OfflineSessionOptions, PacketData } from './types'
import { decode } from './decode'
import { TypedEventEmitter } from './emitter'
import { npcap } from './npcap'

export class NpcapSession extends TypedEventEmitter<{
    packet: [packet: PacketData]
}> {
    /** Raw packets bytes */
    buffer: Buffer

    /** Encoded information about the packet (timestamp, size) */
    header: Buffer
    linkType: LinkType

    session: Session

    constructor(live: boolean, device: string, options: LiveSessionOptions) {
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

        this.buffer = Buffer.alloc(snapLen)
        this.header = Buffer.alloc(16)

        const onPacket = this.onPacket.bind(this)

        this.session = new npcap.Session()

        if (live) {
            this.linkType = this.session.openLive(
                device,
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
                device,
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

    close() {
        this.removeAllListeners()
        this.session.close()
    }

    onPacket() {
        this.emit('packet', {
            buffer: this.buffer,
            header: this.header,
            linkType: this.linkType,
        })
    }

    warningHandler(message: string) {
        console.log(`[warningHandler] ${message}`)
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
