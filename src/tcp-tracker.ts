import EventEmitter from 'node:events'
import type { NpcapDecode } from './decode'

interface SessionData {
    isn?: number
    windowScale?: number
    packets: Record<number, number>
    acks: Record<number, number>
    retrans: Record<number, number>
    nextSeq?: number
    ackSeq?: number
    bytesIp: number
    bytesTcp: number
    bytesPayload: number
}

type SessionStates = 'CLOSED' | 'ESTAB' | 'SYN_SENT' | 'SYN_RECV' | 'FIN_WAIT' | 'CLOSE_WAIT' | 'CLOSING' | 'LAST_ASK'

export class TCPSession extends EventEmitter {
    state: SessionStates = 'CLOSED'

    src?: string
    dst?: string

    currentCapTime: number = 0

    synTime?: number
    missedSyn?: boolean
    connectTime?: number

    closeTime?: number

    send: SessionData = {
        packets: {},
        acks: {},
        retrans: {},

        bytesIp: 0,
        bytesTcp: 0,
        bytesPayload: 0,
    }

    recv: SessionData = {
        packets: {},
        acks: {},
        retrans: {},

        bytesIp: 0,
        bytesTcp: 0,
        bytesPayload: 0,
    }

    track(packet: NpcapDecode) {
        if (!packet.payload.isIPv4() || !packet.payload.payload.isTcp())
            return

        const ip = packet.payload.payload
        const tcp = packet.payload.payload.payload
        const src = `${ip.saddr}:${tcp.sport}`
        const dst = `${ip.daddr}:${tcp.dport}`

        this.currentCapTime = packet.npcapHeader.tvSec + (packet.npcapHeader.tvUsec / 1000000)

        if (this.state === 'CLOSED') {
            this.src = src
            this.dst = dst

            if (tcp.flags.syn && !tcp.flags.ack) {
                // initial SYN??
                this.state = 'SYN_SENT'
            }
            else {
                this.missedSyn = true
                this.connectTime = this.currentCapTime
                this.state = 'ESTAB'
            }

            this.synTime = this.currentCapTime
            this.send.isn = tcp.seqno
            this.send.windowScale = tcp.options?.windowScale || 1 // multipler
            this.send.nextSeq = tcp.seqno + 1
            this.send.bytesIp = ip.headerLength
            this.send.bytesTcp = tcp.headerLength
        }
        else if (tcp.flags.syn && !tcp.flags.ack) {
            this.emit('sin-retry', this)
        }
        else { // not a SYN, so run the state machine
            this[this.state](packet)
        }
    }

    /**
     * State Machine
     */
    SYN_SENT(packet: NpcapDecode) {
        if (!packet.payload.isIPv4() || !packet.payload.payload.isTcp())
            return

        const ip = packet.payload.payload
        const tcp = ip.payload
        const src = `${ip.saddr}:${tcp.sport}`

        if (src === this.dst && tcp.flags.syn && tcp.flags.ack) {
            this.recv.bytesIp += ip.headerLength
            this.recv.bytesTcp += tcp.headerLength
            this.recv.packets[tcp.seqno + 1] = this.currentCapTime
            this.recv.acks[tcp.ackno] = this.currentCapTime
            this.recv.isn = tcp.seqno
            this.recv.windowScale = tcp.options?.windowScale || 1
            this.state = 'SYN_RECV'
        }
        else {
            this.state = 'CLOSED'
            this.emit('reset', this, 'recv') // TODO: Check which direction did reset, probably recv
        }
    }

    SYN_RECV(packet: NpcapDecode) {
        if (!packet.payload.isIPv4() || !packet.payload.payload.isTcp())
            return

        const ip = packet.payload.payload
        const tcp = ip.payload
        const src = `${ip.saddr}:${tcp.sport}`

        // TODO: make sure SYN flag isn't set, also match src and dst
        if (src === this.src && tcp.flags.ack) {
            this.connectTime = this.currentCapTime

            this.send.bytesIp += ip.headerLength
            this.send.bytesTcp += tcp.headerLength
            this.send.acks[tcp.ackno] = this.currentCapTime

            this.emit('start', this)

            this.state = 'ESTAB'
        }
    }

    ESTAB(packet: NpcapDecode) {
        if (!packet.payload.isIPv4() || !packet.payload.payload.isTcp())
            return

        const ip = packet.payload.payload
        const tcp = ip.payload
        const src = `${ip.saddr}:${tcp.sport}`

        // Packet came from the active opener / client
        if (src === this.src) {
            this.send.bytesIp += ip.headerLength
            this.send.bytesTcp += tcp.headerLength

            if (tcp.dataLength > 0) {
                const key = tcp.seqno + tcp.dataLength
                if (this.send.packets[key]) {
                    this.emit('retransmit', this, 'send', key)

                    if (this.send.retrans[key])
                        this.send.retrans[key] += 1
                    else
                        this.send.retrans[key] = 1
                }
                else {
                    this.emit('data-send', this, tcp.data)
                }

                this.send.bytesPayload += tcp.dataLength
                this.send.packets[key] = this.currentCapTime
            }

            if (this.recv.packets[tcp.ackno])
                this.send.acks[tcp.ackno] = this.currentCapTime

            if (tcp.flags.fin)
                this.state = 'FIN_WAIT'
        }
        // Packet come from the passive opener / server
        else if (src === this.dst) {
            this.recv.bytesIp += ip.headerLength
            this.recv.bytesTcp += tcp.headerLength

            if (tcp.dataLength > 0) {
                const key = tcp.seqno + tcp.dataLength

                if (this.recv.packets[key]) {
                    this.emit('retransmit', this, 'recv', key)

                    if (this.recv.retrans[key])
                        this.recv.retrans[key] += 1
                    else
                        this.recv.retrans[key] = 1
                }
                else {
                    this.emit('data-recv', this, tcp.data)
                }

                this.recv.bytesPayload += tcp.dataLength
                this.recv.packets[key] = this.currentCapTime
            }

            if (this.send.packets[tcp.ackno])
                this.recv.acks[tcp.ackno] = this.currentCapTime

            if (tcp.flags.fin)
                this.state = 'CLOSE_WAIT'
        }
        else {
            console.log(`non-matching packet in session ${packet}`)
        }
    }

    FIN_WAIT(packet: NpcapDecode) {
        if (!packet.payload.isIPv4() || !packet.payload.payload.isTcp())
            return

        const ip = packet.payload.payload
        const tcp = ip.payload
        const src = `${ip.saddr}:${tcp.sport}`

        if (src === this.dst && tcp.flags.fin)
            this.state = 'CLOSING'
    }

    CLOSE_WAIT(packet: NpcapDecode) {
        if (!packet.payload.isIPv4() || !packet.payload.payload.isTcp())
            return

        const ip = packet.payload.payload
        const tcp = ip.payload
        const src = `${ip.saddr}:${tcp.sport}`

        if (src === this.src && tcp.flags.fin)
            this.state = 'LAST_ASK'
    }

    LAST_ASK(packet: NpcapDecode) {
        if (!packet.payload.isIPv4() || !packet.payload.payload.isTcp())
            return

        const ip = packet.payload.payload
        const tcp = ip.payload
        const src = `${ip.saddr}:${tcp.sport}`

        if (src === this.dst) {
            this.closeTime = this.currentCapTime
            this.state = 'CLOSED'

            this.emit('end', this)
        }
    }

    CLOSING(packet: NpcapDecode) {
        if (!packet.payload.isIPv4() || !packet.payload.payload.isTcp())
            return

        const ip = packet.payload.payload
        const tcp = ip.payload
        const src = `${ip.saddr}:${tcp.sport}`

        if (src === this.src) {
            this.closeTime = this.currentCapTime
            this.state = 'CLOSED'

            this.emit('end', this)
        }
    }

    CLOSED() {}
}

export class TCPTracker extends EventEmitter {
    session: Record<string, TCPSession> = {}

    trackPacket(packet: NpcapDecode) {
        if (!packet.payload.isIPv4() || !packet.payload.payload.isTcp())
            return

        const ip = packet.payload.payload
        const tcp = packet.payload.payload.payload
        const src = `${ip.saddr}:${tcp.sport}`
        const dst = `${ip.daddr}:${tcp.dport}`

        const key = src < dst
            ? `${src}-${dst}`
            : `${dst}-${src}`

        let isNew = false
        let session = this.session[key]

        if (!session) {
            isNew = true
            session = new TCPSession()
            this.session[key] = session

            session.on('end', () => {
                delete this.session[key]

                console.log(`[TCP Tracker] Session removed ${session.src} -> ${session.dst} (Total: ${Object.keys(this.session).length})`)
            })
        }

        session.track(packet)

        if (isNew)
            this.emit('session', session)
    }
}
