//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

/// An object that controls multiplexing messages to multiple child channels.
final class SSHChannelMultiplexer {
    private var channels: [UInt32: SSHChildChannel]

    enum Quarantine: Equatable { case awaitingOpenResponse, awaitingClose }

    private var erroredChannels: [UInt32: Quarantine]
    private let maximumReservations: Int

    // This object can cause a reference cycle, so we require it to be optional so that we can
    // break the cycle manually.
    private var delegate: SSHMultiplexerDelegate?

    /// The next local channel ID to use. We cycle through them monotonically for now.
    var nextChannelID: UInt32

    private let allocator: ByteBufferAllocator

    private var childChannelInitializer: SSHChildChannel.Initializer?

    /// Whether new channels are allowed. Set to `false` once the parent channel is shut down at the TCP level.
    private var canCreateNewChannels: Bool

    /// The maximum channel data payload size we advertise to peers when opening channels.
    private let maximumPacketSize: UInt32

    init(
        delegate: SSHMultiplexerDelegate,
        allocator: ByteBufferAllocator,
        childChannelInitializer: SSHChildChannel.Initializer?,
        maximumPacketSize: UInt32,
        maximumReservations: Int = Constants.maximumChannelReservations
    ) {
        self.channels = [:]
        self.channels.reserveCapacity(8)
        precondition((1...Constants.maximumChannelReservations).contains(maximumReservations))
        self.maximumReservations = maximumReservations
        self.erroredChannels = [:]
        self.delegate = delegate
        self.nextChannelID = 0
        self.allocator = allocator
        self.childChannelInitializer = childChannelInitializer
        self.canCreateNewChannels = true
        self.maximumPacketSize = maximumPacketSize
    }

    // Time to clean up. We drop references to things that may be keeping us alive.
    // Note that we don't drop the child channels because we expect that they'll be cleaning themselves up.
    func parentHandlerRemoved() {
        self.delegate = nil
        self.childChannelInitializer = nil
        self.canCreateNewChannels = false
        self.erroredChannels.removeAll(keepingCapacity: false)
    }
}

// MARK: Calls from child channels

extension SSHChannelMultiplexer {
    /// An `SSHChildChannel` has issued a write.
    func writeFromChannel(_ message: SSHMessage, _ promise: EventLoopPromise<Void>?) {
        guard let delegate = self.delegate else {
            promise?.fail(ChannelError.ioOnClosedChannel)
            return
        }

        delegate.writeFromChildChannel(message, promise)
    }

    /// An `SSHChildChannel` has issued a flush.
    func childChannelFlush() {
        // Nothing to do.
        guard let delegate = self.delegate else {
            return
        }

        delegate.flushFromChildChannel()
    }

    func childChannelClosed(channelID: UInt32) {
        // This should never return `nil`, but we don't want to assert on it because
        // even if the object was never in the map, nothing bad will happen: it's gone!
        self.channels.removeValue(forKey: channelID)
    }

    func childChannelErrored(channelID: UInt32, quarantine: Quarantine?) {
        self.channels.removeValue(forKey: channelID)
        if self.canCreateNewChannels, let quarantine { self.erroredChannels[channelID] = quarantine }
    }

    var availableChannelReservations: Int {
        self.maximumReservations - self.channels.count - self.erroredChannels.count
    }

    var canReserveChannel: Bool {
        self.availableChannelReservations > (self.delegate?.pendingChannelInitializationsCount ?? 0)
    }

}

// MARK: Calls from SSH handlers.

extension SSHChannelMultiplexer {
    func receiveMessage(_ message: SSHMessage) throws {
        // Quarantine consumes only bounded protocol metadata, never a live
        // child. A late confirmation must be answered without reactivation.
        if let localID = message.recipientChannelID, let phase = self.erroredChannels[localID] {
            switch message {
            case .channelOpenConfirmation(let reply) where phase == .awaitingOpenResponse:
                self.erroredChannels[localID] = .awaitingClose
                self.writeFromChannel(.channelClose(.init(recipientChannel: reply.senderChannel)), nil)
                self.childChannelFlush()
            case .channelOpenFailure where phase == .awaitingOpenResponse,
                .channelClose where phase == .awaitingClose:
                self.erroredChannels.removeValue(forKey: localID)
            default: break
            }
            return
        }
        let channel: SSHChildChannel?

        switch message {
        case .channelOpen(let request):
            guard self.canReserveChannel else {
                self.writeFromChannel(
                    .channelOpenFailure(
                        .init(
                            recipientChannel: request.senderChannel,
                            reasonCode: 4,
                            description: "Channel resource limit",
                            language: "en-US"
                        )
                    ),
                    nil
                )
                self.childChannelFlush()
                return
            }
            channel = try self.openNewChannel(initializer: self.childChannelInitializer)

        case .channelOpenConfirmation(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelOpenFailure(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelEOF(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelClose(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelWindowAdjust(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelData(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelExtendedData(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelRequest(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelSuccess(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelFailure(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        default:
            // Not a channel message, we don't do anything more with this.
            return
        }

        if let channel = channel {
            channel.receiveInboundMessage(message)
        }
    }

    func createChildChannel(
        _ promise: EventLoopPromise<Channel>? = nil,
        channelType: SSHChannelType,
        _ channelInitializer: SSHChildChannel.Initializer?
    ) {
        do {
            let channel = try self.openNewChannel(initializer: channelInitializer)
            channel.configure(userPromise: promise, channelType: channelType)
        } catch {
            promise?.fail(error)
        }
    }

    func parentChannelReadComplete() {
        for channel in self.channels.values {
            channel.receiveParentChannelReadComplete()
        }
    }

    func parentChannelInactive() {
        self.canCreateNewChannels = false
        self.erroredChannels.removeAll(keepingCapacity: false)
        for channel in Array(self.channels.values) {
            channel.parentChannelInactive()
        }
    }

    /// Opens a new channel and adds it to the multiplexer.
    private func openNewChannel(initializer: SSHChildChannel.Initializer?) throws -> SSHChildChannel {
        guard let parentChannel = self.delegate?.channel else {
            throw NIOSSHError.protocolViolation(
                protocolName: "channel",
                violation: "Opening new channel after channel shutdown"
            )
        }

        guard self.canCreateNewChannels else {
            throw NIOSSHError.tcpShutdown
        }

        guard self.canReserveChannel else { throw NIOSSHError.channelResourceLimit }
        // At most reservations+1 candidates are needed, including at wrap.
        var channelID = self.nextChannelID
        for _ in 0...self.maximumReservations {
            channelID = self.nextChannelID
            self.nextChannelID = channelID == UInt32(Int32.max) ? 0 : channelID + 1
            if self.channels[channelID] == nil && self.erroredChannels[channelID] == nil { break }
        }
        precondition(self.channels[channelID] == nil && self.erroredChannels[channelID] == nil)

        var (windowsize, overflow) = Int(self.maximumPacketSize).multipliedReportingOverflow(
            by: Constants.channelWindowSizePacketMultiple
        )
        if overflow || windowsize > Int32.max {
            windowsize = Int(Int32.max)
        }

        let channel = SSHChildChannel(
            allocator: self.allocator,
            parent: parentChannel,
            multiplexer: self,
            initializer: initializer,
            localChannelID: channelID,
            targetWindowSize: Int32(windowsize),
            initialOutboundWindowSize: 0,
            maximumPacketSize: self.maximumPacketSize
        )  // The initial outbound window size is presumed to be 0 until we're told otherwise.

        self.channels[channelID] = channel
        return channel
    }

    private func existingChannel(localID: UInt32) throws -> SSHChildChannel? {
        if let channel = self.channels[localID] {
            return channel
        } else if self.erroredChannels[localID] != nil {
            return nil
        } else {
            throw NIOSSHError.protocolViolation(
                protocolName: "channel",
                violation: "Unexpected request with local channel id \(localID)"
            )
        }
    }
}

/// An internal protocol to encapsulate the object that owns the multiplexer.
protocol SSHMultiplexerDelegate {
    var channel: Channel? { get }

    var pendingChannelInitializationsCount: Int { get }

    func writeFromChildChannel(_: SSHMessage, _: EventLoopPromise<Void>?)

    func flushFromChildChannel()
}

extension SSHMessage {
    fileprivate var recipientChannelID: UInt32? {
        switch self {
        case .channelOpenConfirmation(let m): return m.recipientChannel
        case .channelOpenFailure(let m): return m.recipientChannel
        case .channelEOF(let m): return m.recipientChannel
        case .channelClose(let m): return m.recipientChannel
        case .channelWindowAdjust(let m): return m.recipientChannel
        case .channelData(let m): return m.recipientChannel
        case .channelExtendedData(let m): return m.recipientChannel
        case .channelRequest(let m): return m.recipientChannel
        case .channelSuccess(let m): return m.recipientChannel
        case .channelFailure(let m): return m.recipientChannel
        default: return nil
        }
    }
}
