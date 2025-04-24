import { NpcapSession } from './session'
import type { LiveSessionOptions, OfflineSessionOptions } from './types'

/**
 * Create a live capture session on the specified device
 * and starts capturing packets.
 *
 * @param device The name of the interface to capture packets.
 * @param options Capture options.
 */
export function createSession(device?: string, options: LiveSessionOptions = {}) {
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

export * from './decode'
export * from './npcap'
export * from './session'
export * from './types'
