import EventEmitter from 'events'
import { LinkType, Session, npcap } from './npcap'

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
    snapLength?: number

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
    bufferTimeout?: number

    /**
     * Function that is called whenever Npcap emits a warning.
     * 
     * For example when an interface has no addresses.
     * 
     * @param message The warning that npcap will provide.
     */
    warningHandler?: (message: string) => void,

    /**
     * Set the promiscuous mode.
     * 
     * @default true
     */
    promiscuous?: boolean
}

export interface OfflineSessionOptions extends CommonSessionOptions {

}

export class NpcapSession extends EventEmitter  {
    /** Raw packets bytes */
    buffer: Buffer
    
    /** Encoded information about the packet (timestamp, size) */
    header: Buffer

    session: Session
    linkType: LinkType | undefined = undefined

    emptyReads: number = 0
    
    constructor(live: boolean, public device: string, options: LiveSessionOptions) {
        super()
        
        const {
            filter = '',
            bufferSize = 10485760,
            snapLength = 65535,
            outFile = '',
            monitor = false,
            bufferTimeout = 1000,
            warningHandler = this.warningHandler,
            promiscuous = true
        } = options

        this.buffer = Buffer.alloc(snapLength)
        this.header = Buffer.alloc(16)
        
        this.session = new npcap.Session()

        if (live) {
            this.linkType = this.session.openLive(
                device, 
                filter, 
                bufferSize, 
                snapLength, 
                outFile, 
                this.onPacketReader, 
                monitor, 
                bufferTimeout, 
                warningHandler, 
                promiscuous
            )
            
            // TODO: Another way to avoid this? (maybe https://github.com/mscdex/cap/blob/master/src/binding.cc#L288 ??)
            this.session.readCallback = () => {
                let readCount = this.session.dispatch(this.buffer, this.header)
                if (readCount < 1) {
                    this.emptyReads++
                }
            }

            process.nextTick(this.session.readCallback) // Kickstart to prevent races
        }
    }

    warningHandler() {
        
    }

    onPacketReader() {
        this.emit('packet', {
            buffer: this.buffer,
            header: this.header,
            linkType: this.linkType
        })
    }

    close() {
        this.removeAllListeners()
        this.session.close()
    }
}

/**
 * Create a live capture session on the specified device
 * and starts capturing packets.
 * 
 * @param device The name of the interface to capture packets.
 * @param options Capture options.
 * 
 * @returns 
 */
export const createSession = (device: string, options: LiveSessionOptions = {}) => {
    return new NpcapSession(true, device, options);
}

/**
 * Starts an 'offline' capture session that emits packets,
 * read from a capture file.
 * 
 * @param path File path to the `.pcap` file to read.
 * @param options Capture options.
 */
export const createOfflineSession = (path: string, options: OfflineSessionOptions = {}) => {
    return new NpcapSession(false, path, options);
}

const session = createSession("\\Device\\NPF_{56761211-7574-48DB-952D-1E8C714F31E6}", { filter: 'udp or tcp' })
console.log(`Listening on ${session.device}, linkType: ${session.linkType}`)

session.on('packet', (rawPacket) => {
    console.log(rawPacket)
})

setTimeout(() => {
    console.log('Close connection')
    session.close()
}, 10_000)
