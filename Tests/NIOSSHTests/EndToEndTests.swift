//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSH

enum EndToEndTestError: Error, Equatable {
    case unableToCreateChildChannel
    case injectedTerminalWriteFailure
}

class BackToBackEmbeddedChannel {
    private(set) var client: EmbeddedChannel
    private(set) var server: EmbeddedChannel
    private var loop: EmbeddedEventLoop

    private(set) var activeServerChannels: [Channel]

    var clientSSHHandler: NIOSSHHandler? {
        try? self.client.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
    }

    var serverSSHHandler: NIOSSHHandler? {
        try? self.server.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
    }

    init() {
        self.loop = EmbeddedEventLoop()
        self.client = EmbeddedChannel(loop: self.loop)
        self.server = EmbeddedChannel(loop: self.loop)
        self.activeServerChannels = []
    }

    func run() {
        self.loop.run()
    }

    func interactInMemory() throws {
        var workToDo = true

        while workToDo {
            workToDo = false

            self.loop.run()
            let clientDatum = try self.client.readOutbound(as: IOData.self)
            let serverDatum = try self.server.readOutbound(as: IOData.self)

            if let clientMsg = clientDatum {
                try self.server.writeInbound(clientMsg)
                workToDo = true
            }

            if let serverMsg = serverDatum {
                try self.client.writeInbound(serverMsg)
                workToDo = true
            }
        }
    }

    func advanceTime(by increment: TimeAmount) {
        self.loop.advanceTime(by: increment)
    }

    func activate() throws {
        // A weird wrinkle of embedded channel is that it only properly activates on connect.
        try self.client.connect(to: .init(unixDomainSocketPath: "/fake")).wait()
        try self.server.connect(to: .init(unixDomainSocketPath: "/fake")).wait()
    }

    func configureWithHarness(_ harness: TestHarness) throws {
        let clientHandler = NIOSSHHandler(
            role: .client(
                .init(
                    userAuthDelegate: harness.clientAuthDelegate,
                    serverAuthDelegate: harness.clientServerAuthDelegate,
                    globalRequestDelegate: harness.clientGlobalRequestDelegate
                )
            ),
            allocator: self.client.allocator,
            inboundChildChannelInitializer: nil
        )
        let serverHandler = NIOSSHHandler(
            role: .server(
                .init(
                    hostKeys: harness.serverHostKeys,
                    userAuthDelegate: harness.serverAuthDelegate,
                    globalRequestDelegate: harness.serverGlobalRequestDelegate,
                    banner: harness.serverAuthBanner
                )
            ),
            allocator: self.server.allocator
        ) { channel, _ in
            self.activeServerChannels.append(channel)
            let boxedSelf = NIOLoopBound(self, eventLoop: channel.eventLoop)
            channel.closeFuture.whenComplete { _ in
                boxedSelf.value.activeServerChannels.removeAll(where: { $0 === channel })
            }
            return channel.eventLoop.makeSucceededFuture(())
        }

        try self.client.pipeline.syncOperations.addHandler(clientHandler)
        try self.server.pipeline.syncOperations.addHandler(serverHandler)
    }

    func finish() throws {
        XCTAssertNoThrow(XCTAssertTrue(try self.client.finish(acceptAlreadyClosed: true).isClean))
        XCTAssertNoThrow(XCTAssertTrue(try self.server.finish(acceptAlreadyClosed: true).isClean))
        XCTAssertNoThrow(try self.loop.syncShutdownGracefully())
    }

    func createNewChannel() throws -> Channel {
        var clientChannel = Optional<Channel>.none
        self.clientSSHHandler?.createChannel { channel, _ in
            clientChannel = channel
            return channel.eventLoop.makeSucceededFuture(())
        }

        guard let channel = clientChannel else {
            XCTFail("Unable to create child channel")
            throw EndToEndTestError.unableToCreateChildChannel
        }

        return channel
    }
}

/// A straightforward test harness.
struct TestHarness {
    var clientAuthDelegate: NIOSSHClientUserAuthenticationDelegate = InfinitePasswordDelegate()

    var clientServerAuthDelegate: NIOSSHClientServerAuthenticationDelegate = AcceptAllHostKeysDelegate()

    var clientGlobalRequestDelegate: GlobalRequestDelegate?

    var serverAuthDelegate: NIOSSHServerUserAuthenticationDelegate = DenyThenAcceptDelegate(messagesToDeny: 0)

    var serverGlobalRequestDelegate: GlobalRequestDelegate?

    var serverHostKeys: [NIOSSHPrivateKey] = [.init(ed25519Key: .init())]

    var serverAuthBanner: SSHServerConfiguration.UserAuthBanner?
}

final class UserEventExpecter: ChannelInboundHandler {
    typealias InboundIn = Any

    var userEvents: [Any] = []

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        self.userEvents.append(event)
        context.fireUserInboundEventTriggered(event)
    }
}

final class PrivateKeyClientAuth: NIOSSHClientUserAuthenticationDelegate {
    private var key: NIOSSHPrivateKey?

    init(_ key: NIOSSHPrivateKey) {
        self.key = key
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        guard availableMethods.contains(.publicKey), let key = self.key else {
            nextChallengePromise.succeed(nil)
            return
        }

        self.key = nil
        nextChallengePromise.succeed(
            .init(username: "foo", serviceName: "ssh-connection", offer: .privateKey(.init(privateKey: key)))
        )
    }
}

final class ExpectPublicKeyAuth: NIOSSHServerUserAuthenticationDelegate {
    private var key: NIOSSHPublicKey

    init(_ key: NIOSSHPublicKey) {
        self.key = key
    }

    let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods = .publicKey

    func requestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
    ) {
        guard case .publicKey(let actualKey) = request.request else {
            responsePromise.succeed(.failure)
            return
        }

        if actualKey.publicKey == self.key {
            responsePromise.succeed(.success)
        } else {
            responsePromise.succeed(.failure)
        }
    }
}

class EndToEndTests: XCTestCase {
    var channel: BackToBackEmbeddedChannel!

    override func setUp() {
        self.channel = BackToBackEmbeddedChannel()
    }

    override func tearDown() {
        try? self.channel.finish()
        self.channel = nil
    }

    /// This test validates that all the channel requests round-trip appropriately.
    func testChannelRequests() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Create a channel.
        let clientChannel = try self.channel.createNewChannel()
        XCTAssertNoThrow(try self.channel.interactInMemory())
        guard let serverChannel = self.channel.activeServerChannels.first else {
            XCTFail("Server channel not created")
            return
        }

        let userEventRecorder = UserEventExpecter()
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(userEventRecorder))

        func helper<Event: Equatable>(_ event: Event) {
            let clientSent = NIOLoopBoundBox(false, eventLoop: clientChannel.eventLoop)

            let promise = clientChannel.eventLoop.makePromise(of: Void.self)
            clientChannel.pipeline.syncOperations.triggerUserOutboundEvent(event, promise: promise)
            promise.futureResult.whenSuccess { clientSent.value = true }
            XCTAssertNoThrow(try self.channel.interactInMemory())

            XCTAssertTrue(clientSent.value)
            XCTAssertEqual(userEventRecorder.userEvents.last as? Event?, event)
        }

        helper(SSHChannelRequestEvent.ExecRequest(command: "uname -a", wantReply: true))
        helper(SSHChannelRequestEvent.EnvironmentRequest(wantReply: true, name: "foo", value: "bar"))
        helper(SSHChannelRequestEvent.ExitStatus(exitStatus: 5))
        helper(
            SSHChannelRequestEvent.PseudoTerminalRequest(
                wantReply: true,
                term: "vt100",
                terminalCharacterWidth: 80,
                terminalRowHeight: 24,
                terminalPixelWidth: 0,
                terminalPixelHeight: 0,
                terminalModes: .init([.ECHO: 5])
            )
        )
        helper(SSHChannelRequestEvent.ShellRequest(wantReply: true))
        helper(
            SSHChannelRequestEvent.ExitSignal(
                signalName: "ILL",
                errorMessage: "illegal instruction",
                language: "en",
                dumpedCore: true
            )
        )
        helper(SSHChannelRequestEvent.SubsystemRequest(subsystem: "file transfer", wantReply: false))
        helper(
            SSHChannelRequestEvent.WindowChangeRequest(
                terminalCharacterWidth: 0,
                terminalRowHeight: 0,
                terminalPixelWidth: 720,
                terminalPixelHeight: 480
            )
        )
        helper(SSHChannelRequestEvent.LocalFlowControlRequest(clientCanDo: true))
        helper(SSHChannelRequestEvent.SignalRequest(signal: "USR1"))
        helper(ChannelSuccessEvent())
        helper(ChannelFailureEvent())
    }

    func testGlobalRequestWithDefaultDelegate() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        func helper(_ request: GlobalRequest.TCPForwardingRequest) throws -> GlobalRequest.TCPForwardingResponse? {
            let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
            self.channel.clientSSHHandler?.sendTCPForwardingRequest(request, promise: promise)
            try self.channel.interactInMemory()
            return try promise.futureResult.wait()
        }

        // The default delegate rejects everything.
        XCTAssertThrowsError(try helper(.listen(host: "localhost", port: 8765))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .globalRequestRefused)
        }
        XCTAssertThrowsError(try helper(.cancel(host: "localhost", port: 8765))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .globalRequestRefused)
        }
    }

    func testGlobalRequestWithCustomDelegate() throws {
        class CustomGlobalRequestDelegate: GlobalRequestDelegate {
            var requests: [GlobalRequest.TCPForwardingRequest] = []

            var port: Int? = 0

            func tcpForwardingRequest(
                _ request: GlobalRequest.TCPForwardingRequest,
                handler: NIOSSHHandler,
                promise: EventLoopPromise<GlobalRequest.TCPForwardingResponse>
            ) {
                self.requests.append(request)
                let port = self.port
                self.port = nil
                promise.succeed(.init(boundPort: port))
            }
        }

        let customDelegate = CustomGlobalRequestDelegate()
        var harness = TestHarness()
        harness.serverGlobalRequestDelegate = customDelegate

        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        func helper(_ request: GlobalRequest.TCPForwardingRequest) throws -> GlobalRequest.TCPForwardingResponse? {
            let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
            self.channel.clientSSHHandler?.sendTCPForwardingRequest(request, promise: promise)
            try self.channel.interactInMemory()
            return try promise.futureResult.wait()
        }

        // This delegate accepts things.
        let firstResponse = try helper(.listen(host: "localhost", port: 8765))
        let secondResponse = try helper(.cancel(host: "localhost", port: 8765))

        XCTAssertEqual(firstResponse, GlobalRequest.TCPForwardingResponse(boundPort: 0))
        XCTAssertEqual(secondResponse, GlobalRequest.TCPForwardingResponse(boundPort: nil))

        XCTAssertEqual(
            customDelegate.requests,
            [.listen(host: "localhost", port: 8765), .cancel(host: "localhost", port: 8765)]
        )
    }

    func testUnknownGlobalRequestCanTriggerResponse() throws {
        // This test verifies that, when the boolean `wantReply` is true, an error reply is sent back

        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Force unwrap is used, because this is a test and the handler must exist
        let clientSSHHandler = self.channel.clientSSHHandler!

        // The arbitrary number of 12 has no meaning here
        // What _is_ important is that the amount of added bytes is greater than 0
        var randomPayload = self.channel.client.allocator.buffer(capacity: 12)
        randomPayload.writeBytes(Array(randomBytes: 12))

        let firstReply = self.channel.client.eventLoop.makePromise(of: ByteBuffer?.self)
        clientSSHHandler.sendGlobalRequestMessage(
            .init(wantReply: true, type: .unknown("test", randomPayload)),
            promise: firstReply
        )

        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertThrowsError(try firstReply.futureResult.wait())

        let secondReply = self.channel.client.eventLoop.makePromise(of: ByteBuffer?.self)
        clientSSHHandler.sendGlobalRequestMessage(
            .init(wantReply: false, type: .unknown("test", randomPayload)),
            promise: secondReply
        )

        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertNil(try secondReply.futureResult.wait())
    }

    func testGlobalRequestTooEarlyIsDelayed() throws {
        let completed = NIOLoopBoundBox(false, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
        promise.futureResult.whenComplete { _ in completed.value = true }

        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))

        // Issue a forwarding request early. This should be queued.
        self.channel.clientSSHHandler?.sendTCPForwardingRequest(
            .listen(host: "localhost", port: 2222),
            promise: promise
        )
        XCTAssertFalse(completed.value)

        // Activate. This will complete the forwarding request.
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertTrue(completed.value)
    }

    func testGlobalRequestsAreCancelledIfRemoved() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Enqueue a global request.
        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
        promise.futureResult.whenFailure { error in err.value = error }
        self.channel.clientSSHHandler?.sendTCPForwardingRequest(
            .listen(host: "localhost", port: 1234),
            promise: promise
        )
        XCTAssertNil(err.value)

        self.channel.client.close(promise: nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(err.value as? ChannelError, .eof)
    }

    func testNeverStartedGlobalRequestsAreCancelledIfRemoved() throws {
        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
        promise.futureResult.whenFailure { error in err.value = error }

        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))

        // Enqueue a forwarding request
        self.channel.clientSSHHandler?.sendTCPForwardingRequest(
            .listen(host: "localhost", port: 1234),
            promise: promise
        )
        XCTAssertNil(err.value)

        // Now close the channel.
        self.channel.client.close(promise: nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(err.value as? ChannelError, .eof)
    }

    func testGlobalRequestAfterCloseFails() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Get an early ref to the handler.
        let handler = self.channel.clientSSHHandler

        // Close.
        self.channel.client.close(promise: nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Enqueue a global request.
        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
        promise.futureResult.whenFailure { error in err.value = error }
        handler?.sendTCPForwardingRequest(.listen(host: "localhost", port: 1234), promise: promise)
        XCTAssertEqual(err.value as? ChannelError, .ioOnClosedChannel)
    }

    func testSecureEnclaveKeys() throws {
        // This is a quick end-to-end test that validates that we support secure enclave private keys
        // on appropriate platforms.
        #if canImport(Darwin)
        // If we can't create this key, we skip the test.
        let key: NIOSSHPrivateKey
        do {
            key = try .init(secureEnclaveP256Key: .init())
        } catch {
            return
        }

        // We use the Secure Enclave keys for everything, just because we can.
        var harness = TestHarness()
        harness.serverHostKeys = [key]
        harness.clientAuthDelegate = PrivateKeyClientAuth(key)
        harness.serverAuthDelegate = ExpectPublicKeyAuth(key.publicKey)

        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Create a channel, again, just because we can.
        _ = try self.channel.createNewChannel()
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
        #endif
    }

    func testSupportClientInitiatedRekeying() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Initiate re-keying on the client.
        XCTAssertNoThrow(try self.channel.clientSSHHandler!._rekey())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // We should be able to send a message here.
        XCTAssertEqual(self.channel.activeServerChannels.count, 0)
        self.channel.clientSSHHandler?.createChannel(nil, nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
    }

    func testSupportServerInitiatedRekeying() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Initiate re-keying on the server.
        XCTAssertNoThrow(try self.channel.serverSSHHandler!._rekey())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // We should be able to send a message here.
        XCTAssertEqual(self.channel.activeServerChannels.count, 0)
        self.channel.clientSSHHandler?.createChannel(nil, nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
    }

    func testDelayedHostKeyValidation() throws {
        class DelayedValidationDelegate: NIOSSHClientServerAuthenticationDelegate {
            var validationCount = 0

            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                // Short delay here, but we'll be forced to wait.
                let eventLoopSelf = NIOLoopBoundBox(
                    self,
                    eventLoop: validationCompletePromise.futureResult.eventLoop
                )
                validationCompletePromise.futureResult.eventLoop.scheduleTask(in: .milliseconds(100)) {
                    eventLoopSelf.value.validationCount += 1
                    validationCompletePromise.succeed(())
                }
            }
        }

        let delegate = DelayedValidationDelegate()
        var harness = TestHarness()
        harness.clientServerAuthDelegate = delegate

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // This will not be active yet! Advance time and interact again.
        XCTAssertEqual(delegate.validationCount, 0)
        self.channel.advanceTime(by: .milliseconds(100))
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(delegate.validationCount, 1)

        // We should be able to send a message here.
        XCTAssertEqual(self.channel.activeServerChannels.count, 0)
        self.channel.clientSSHHandler?.createChannel(nil, nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
    }

    func testHostKeyRejection() throws {
        enum TestError: Error {
            case bang
        }

        struct RejectDelegate: NIOSSHClientServerAuthenticationDelegate {
            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                validationCompletePromise.fail(TestError.bang)
            }
        }

        let errorCatcher = ErrorLoggingHandler()
        var harness = TestHarness()
        harness.clientServerAuthDelegate = RejectDelegate()

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(errorCatcher))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertThrowsError(try self.channel.interactInMemory()) { error in
            XCTAssertEqual(error as? TestError, .bang)
        }

        XCTAssertEqual(errorCatcher.errors.count, 1)
        XCTAssertEqual(errorCatcher.errors.first as? TestError, .bang)
    }

    func testCreateChannelBeforeIncompleteHandshakeFails() throws {
        enum TestError: Error {
            case bang
        }

        struct RejectDelegate: NIOSSHClientServerAuthenticationDelegate {
            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                validationCompletePromise.fail(TestError.bang)
            }
        }

        var harness = TestHarness()
        harness.clientServerAuthDelegate = RejectDelegate()

        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(ErrorClosingHandler()))

        // Get an early ref to the handler and try to create a child channel.
        let handler = self.channel.clientSSHHandler

        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: Channel.self)
        promise.futureResult.whenFailure { error in err.value = error }
        handler!.createChannel(promise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }
        XCTAssertNil(err.value)

        // Activation errors.
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertThrowsError(try self.channel.interactInMemory()) { error in
            XCTAssertEqual(error as? TestError, .bang)
        }
        self.channel.run()
        XCTAssertEqual(err.value as? ChannelError?, .eof)
    }

    func testCreateChannelAfterDisconnectFailsWithEventLoopTick() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Initiate disconnection on the client.
        XCTAssertNoThrow(try self.channel.clientSSHHandler!._disconnect())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Attempting to create a child channel should immediately fail.
        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: Channel.self)
        promise.futureResult.whenFailure { error in err.value = error }
        self.channel.clientSSHHandler!.createChannel(promise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }
        self.channel.run()

        XCTAssertNotNil(err.value)
        XCTAssertEqual((err.value as? NIOSSHError)?.type, .creatingChannelAfterClosure)
    }

    func testCreateChannelAfterDisconnectFailsWithoutEventLoopTick() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Initiate disconnection on the client.
        XCTAssertNoThrow(try self.channel.clientSSHHandler!._disconnect())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Attempting to create a child channel should immediately fail.
        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: Channel.self)
        promise.futureResult.whenFailure { error in err.value = error }
        self.channel.clientSSHHandler!.createChannel(promise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }
        self.channel.run()

        XCTAssertNotNil(err.value)
        XCTAssertEqual((err.value as? NIOSSHError)?.type, .creatingChannelAfterClosure)
    }

    func testHandshakeSuccess() throws {
        class ClientHandshakeHandler: ChannelInboundHandler {
            typealias InboundIn = Any

            let promise: EventLoopPromise<Void>

            init(promise: EventLoopPromise<Void>) {
                self.promise = promise
            }

            func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
                if event is UserAuthSuccessEvent {
                    self.promise.succeed(())
                }
            }
        }

        let promise = self.channel.client.eventLoop.makePromise(of: Void.self)
        let handshaker = ClientHandshakeHandler(promise: promise)

        let harness = TestHarness()

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(handshaker))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertNoThrow(try promise.futureResult.wait())
    }

    func testServerDoesNotSendBanner() throws {
        class ClientHandshakeHandler: ChannelInboundHandler {
            typealias InboundIn = Any

            var promise: EventLoopPromise<Void>?

            init(promise: EventLoopPromise<Void>) {
                self.promise = promise
            }

            func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
                guard let promise = self.promise else { return }
                self.promise = nil

                if event is NIOUserAuthBannerEvent {
                    promise.fail(HandshakeFailure.missingBanner)
                } else if event is UserAuthSuccessEvent {
                    promise.succeed(())
                }
            }

            enum HandshakeFailure: Error {
                case missingBanner
            }
        }

        let promise = self.channel.client.eventLoop.makePromise(of: Void.self)
        let handshaker = ClientHandshakeHandler(promise: promise)

        var harness = TestHarness()
        harness.serverAuthBanner = nil

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(handshaker))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertNoThrow(try promise.futureResult.wait())
    }

    func testCorrectBannerReceived() throws {
        class ClientHandshakeHandler: ChannelInboundHandler {
            typealias InboundIn = Any

            static let expectedAuthBannerMessage = "This is a demo user auth banner."
            static let expectedAuthBannerLanguageTag = "en"

            var promise: EventLoopPromise<(String, String)>?

            init(promise: EventLoopPromise<(String, String)>) {
                self.promise = promise
            }

            func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
                guard let promise = self.promise else { return }
                self.promise = nil

                if let event = event as? NIOUserAuthBannerEvent {
                    promise.succeed((event.message, event.languageTag))
                } else if event is UserAuthSuccessEvent {
                    promise.fail(HandshakeFailure.missingBanner)
                }
            }

            enum HandshakeFailure: Error {
                case missingBanner
            }
        }

        let promise = self.channel.client.eventLoop.makePromise(of: (String, String).self)
        let handshaker = ClientHandshakeHandler(promise: promise)

        var harness = TestHarness()
        harness.serverAuthBanner = .init(
            message: ClientHandshakeHandler.expectedAuthBannerMessage,
            languageTag: ClientHandshakeHandler.expectedAuthBannerLanguageTag
        )

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(handshaker))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        var banner = ("", "")
        XCTAssertNoThrow(banner = try promise.futureResult.wait())
        XCTAssertEqual(banner.0, ClientHandshakeHandler.expectedAuthBannerMessage)
        XCTAssertEqual(banner.1, ClientHandshakeHandler.expectedAuthBannerLanguageTag)
    }

    func testHandshakeFailure() throws {
        class ClientHandshakeHandler: ChannelInboundHandler {
            typealias InboundIn = Any

            let promise: EventLoopPromise<Void>

            init(promise: EventLoopPromise<Void>) {
                self.promise = promise
            }

            func errorCaught(context: ChannelHandlerContext, error: Error) {
                self.promise.fail(error)
            }
        }

        enum TestError: Error {
            case bang
        }

        struct BadPasswordDelegate: NIOSSHClientUserAuthenticationDelegate {
            func nextAuthenticationType(
                availableMethods: NIOSSHAvailableUserAuthenticationMethods,
                nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
            ) {
                nextChallengePromise.fail(TestError.bang)
            }
        }

        var harness = TestHarness()
        harness.clientAuthDelegate = BadPasswordDelegate()

        let promise = self.channel.client.eventLoop.makePromise(of: Void.self)
        let handshaker = ClientHandshakeHandler(promise: promise)

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(handshaker))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertThrowsError(try promise.futureResult.wait()) { error in
            XCTAssertEqual(error as? TestError, TestError.bang)
        }
    }
}

extension EndToEndTests {
    func testPublicLocalAbortDoesNotNeedPeerProgressAndSiblingStillTransfers() throws {
        try self.channel.configureWithHarness(TestHarness())
        try self.channel.activate()
        try self.channel.interactInMemory()
        let first = try self.channel.createNewChannel()
        try self.channel.interactInMemory()
        let sibling = try self.channel.createNewChannel()
        try self.channel.interactInMemory()
        let remoteSibling = try XCTUnwrap(self.channel.activeServerChannels.last)
        let reads = NIOLoopBound(ReadRecordingHandler(), eventLoop: remoteSibling.eventLoop)
        try remoteSibling.pipeline.syncOperations.addHandler(reads.value)
        let terminal = NIOLoopBoundBox<Result<Void, Error>?>(nil, eventLoop: first.eventLoop)
        first.closeFuture.whenComplete { terminal.value = $0 }
        first.triggerUserOutboundEvent(SSHChannelAbortEvent(), promise: nil)
        // Drive local cleanup ONLY: the encrypted peer has not received our
        // CLOSE, so it cannot possibly have sent its acknowledgement yet.
        self.channel.run()
        if case .failure(let error)? = terminal.value {
            XCTAssertEqual((error as? NIOSSHError)?.type, .channelAborted)
        } else {
            XCTFail("Local abort waited for remote SSH progress")
        }
        XCTAssertFalse(first.isActive)
        XCTAssertTrue(self.channel.client.isActive)
        XCTAssertTrue(self.channel.server.isActive)
        XCTAssertTrue(sibling.isActive)
        let payload = ByteBuffer(string: "sibling survives local abort")
        sibling.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(payload)), promise: nil)
        try self.channel.interactInMemory()
        XCTAssertEqual(reads.value.reads, [.init(type: .channel, data: .byteBuffer(payload))])
        XCTAssertTrue(sibling.isActive)
    }
}

extension EndToEndTests {
    func testAuthenticatedQueueDrainRetainsCapacityDuringReentrantInitializer() throws {
        try self.channel.configureWithHarness(TestHarness())
        let handler = try XCTUnwrap(self.channel.clientSSHHandler)
        let initialized = NIOLoopBoundBox(0, eventLoop: self.channel.client.eventLoop)
        let completed = NIOLoopBoundBox(0, eventLoop: self.channel.client.eventLoop)
        let failures = NIOLoopBoundBox(0, eventLoop: self.channel.client.eventLoop)
        let refused = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let boundHandler = NIOLoopBound(handler, eventLoop: self.channel.client.eventLoop)
        for _ in 0..<Constants.maximumChannelReservations {
            let promise = self.channel.client.eventLoop.makePromise(of: Channel.self)
            promise.futureResult.whenComplete { result in
                completed.value += 1
                if case .failure = result { failures.value += 1 }
            }
            handler.createChannel(promise) { child, _ in
                initialized.value += 1
                if initialized.value == 1 {
                    let extra = child.eventLoop.makePromise(of: Channel.self)
                    extra.futureResult.whenFailure { refused.value = $0 }
                    boundHandler.value.createChannel(extra) { unexpected, _ in
                        XCTFail("Reentrant initializer bypassed queued reservation accounting")
                        return unexpected.eventLoop.makeSucceededFuture(())
                    }
                }
                return child.eventLoop.makeSucceededFuture(())
            }
        }
        XCTAssertEqual(initialized.value, 0)
        XCTAssertEqual(handler.pendingChannelInitializationsCount, Constants.maximumChannelReservations)
        try self.channel.activate()
        try self.channel.interactInMemory()
        XCTAssertEqual(initialized.value, Constants.maximumChannelReservations)
        XCTAssertEqual(completed.value, Constants.maximumChannelReservations)
        XCTAssertEqual(failures.value, 0)
        XCTAssertEqual(handler.pendingChannelInitializationsCount, 0)
        XCTAssertEqual((refused.value as? NIOSSHError)?.type, .channelResourceLimit)
        XCTAssertTrue(self.channel.client.isActive)
        XCTAssertTrue(self.channel.server.isActive)
    }
}

extension EndToEndTests {
    func testAbortDuringRealRekeyEventuallyClosesPeerAndPreservesSibling() throws {
        for serverInitiated in [false, true] {
            let pair = BackToBackEmbeddedChannel()
            defer { XCTAssertNoThrow(try pair.finish()) }
            try pair.configureWithHarness(TestHarness())
            try pair.activate()
            try pair.interactInMemory()
            let target = try pair.createNewChannel()
            try pair.interactInMemory()
            let remoteTarget = try XCTUnwrap(pair.activeServerChannels.first)
            let sibling = try pair.createNewChannel()
            try pair.interactInMemory()
            let remoteSibling = try XCTUnwrap(pair.activeServerChannels.last)
            let reads = NIOLoopBound(ReadRecordingHandler(), eventLoop: remoteSibling.eventLoop)
            try remoteSibling.pipeline.syncOperations.addHandler(reads.value)
            if serverInitiated {
                try XCTUnwrap(pair.serverSSHHandler)._rekey()
                // Deliver only the initiating KEXINIT, never complete rekey.
                let kex = try XCTUnwrap(pair.server.readOutbound(as: IOData.self))
                try pair.client.writeInbound(kex)
            } else {
                try XCTUnwrap(pair.clientSSHHandler)._rekey()
            }
            XCTAssertFalse(try XCTUnwrap(pair.clientSSHHandler).canSendChannelControlMessages)
            let terminal = NIOLoopBoundBox<Result<Void, Error>?>(nil, eventLoop: target.eventLoop)
            target.closeFuture.whenComplete { terminal.value = $0 }
            target.triggerUserOutboundEvent(SSHChannelAbortEvent(), promise: nil)
            pair.run()
            if case .failure(let error)? = terminal.value {
                XCTAssertEqual((error as? NIOSSHError)?.type, .channelAborted)
            } else {
                XCTFail("Local abort must join without completing rekey")
            }
            XCTAssertFalse(target.isActive)
            XCTAssertTrue(remoteTarget.isActive)
            XCTAssertTrue(sibling.isActive)
            XCTAssertTrue(pair.client.isActive)
            XCTAssertTrue(pair.server.isActive)
            try pair.interactInMemory()
            XCTAssertFalse(remoteTarget.isActive)
            XCTAssertEqual(pair.activeServerChannels.count, 1)
            let payload = ByteBuffer(string: "sibling after abort during real rekey")
            sibling.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(payload)), promise: nil)
            try pair.interactInMemory()
            XCTAssertEqual(reads.value.reads, [.init(type: .channel, data: .byteBuffer(payload))])
            XCTAssertTrue(sibling.isActive)
            XCTAssertTrue(pair.client.isActive)
            XCTAssertTrue(pair.server.isActive)
        }
    }
}

private final class DelayedTerminalWriteFailure: ChannelOutboundHandler, Sendable {
    typealias OutboundIn = Any
    let writes: NIOLoopBoundBox<Int>

    init(writes: NIOLoopBoundBox<Int>) { self.writes = writes }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        self.writes.value += 1
        // Actual handler-owned promise, failed AFTER context.write returns.
        // This is deterministic fault injection, not a real network failure.
        context.eventLoop.execute { promise?.fail(EndToEndTestError.injectedTerminalWriteFailure) }
    }
}

extension EndToEndTests {
    func testUnreservedTerminalAsyncWriteFailurePreservesCallerAndClosesTransportOnce() throws {
        for openFailure in [false, true] {
            for withCaller in [false, true] {
                let pair = BackToBackEmbeddedChannel()
                defer { XCTAssertNoThrow(try pair.finish()) }
                try pair.configureWithHarness(TestHarness())
                try pair.activate()
                try pair.interactInMemory()
                let handler = try XCTUnwrap(pair.clientSSHHandler)
                let writes = NIOLoopBoundBox(0, eventLoop: pair.client.eventLoop)
                let outcomes = NIOLoopBoundBox(0, eventLoop: pair.client.eventLoop)
                let errors = ErrorLoggingHandler()
                try pair.client.pipeline.syncOperations.addHandler(
                    DelayedTerminalWriteFailure(writes: writes),
                    position: .first
                )
                try pair.client.pipeline.syncOperations.addHandler(errors)
                let caller = withCaller ? pair.client.eventLoop.makePromise(of: Void.self) : nil
                caller?.futureResult.whenFailure { error in
                    XCTAssertEqual(error as? EndToEndTestError, .injectedTerminalWriteFailure)
                    outcomes.value += 1
                }
                let message: SSHMessage =
                    openFailure
                    ? .channelOpenFailure(
                        .init(recipientChannel: 9, reasonCode: 4, description: "limit", language: "en")
                    )
                    : .channelClose(.init(recipientChannel: 9))
                handler.writeFromChildChannel(message, caller)
                XCTAssertEqual(writes.value, 1)
                XCTAssertEqual(outcomes.value, 0)
                XCTAssertTrue(pair.client.isActive)
                pair.run()
                XCTAssertEqual(outcomes.value, withCaller ? 1 : 0)
                XCTAssertEqual(errors.errors.count, 1)
                XCTAssertEqual(errors.errors.first as? EndToEndTestError, .injectedTerminalWriteFailure)
                XCTAssertFalse(pair.client.isActive)
                // A duplicate failure after parent teardown is not a new error.
                handler.terminalControlWriteFailed(EndToEndTestError.injectedTerminalWriteFailure)
                XCTAssertThrowsError(try pair.client.throwIfErrorCaught())
                XCTAssertNoThrow(try pair.client.throwIfErrorCaught())
                pair.run()
                XCTAssertEqual(writes.value, 1)
                XCTAssertEqual(outcomes.value, withCaller ? 1 : 0)
                XCTAssertEqual(errors.errors.count, 1)
            }
        }
    }
}

extension EndToEndTests {
    func testOrdinaryDataTrafficDoesNotScheduleTerminalControlTasks() throws {
        let pair = BackToBackEmbeddedChannel()
        defer { XCTAssertNoThrow(try pair.finish()) }
        try pair.configureWithHarness(TestHarness())
        try pair.activate()
        try pair.interactInMemory()
        let child = try pair.createNewChannel()
        try pair.interactInMemory()
        let peer = try XCTUnwrap(pair.activeServerChannels.first)
        let reads = NIOLoopBound(ReadRecordingHandler(), eventLoop: peer.eventLoop)
        try peer.pipeline.syncOperations.addHandler(reads.value)
        let client = try XCTUnwrap(pair.clientSSHHandler)
        let server = try XCTUnwrap(pair.serverSSHHandler)
        let payload = SSHChannelData(type: .channel, data: .byteBuffer(ByteBuffer(string: "ordinary data")))
        for _ in 0..<8 {
            child.writeAndFlush(payload, promise: nil)
            // Observe immediately, before any queued task could clear the flag.
            XCTAssertFalse(client.terminalControlDrainScheduled)
            let packet = try XCTUnwrap(pair.client.readOutbound(as: IOData.self))
            try pair.server.writeInbound(packet)
            XCTAssertFalse(server.terminalControlDrainScheduled)
        }
        XCTAssertEqual(reads.value.reads, Array(repeating: payload, count: 8))
        XCTAssertTrue(child.isActive)
        XCTAssertTrue(peer.isActive)
    }
}

private final class AbortChildOnParentFlush: ChannelOutboundHandler, Sendable {
    typealias OutboundIn = Any
    let child: NIOLoopBound<Channel>
    let fired: NIOLoopBoundBox<Bool>

    init(child: Channel) {
        self.child = NIOLoopBound(child, eventLoop: child.eventLoop)
        self.fired = NIOLoopBoundBox(false, eventLoop: child.eventLoop)
    }

    func flush(context: ChannelHandlerContext) {
        if !self.fired.value {
            self.fired.value = true
            self.child.value.triggerUserOutboundEvent(SSHChannelAbortEvent(), promise: nil)
        }
        context.flush()
    }
}

extension EndToEndTests {
    func testAbortFromParentFlushDrainsReentrantCloseWithoutFurtherIO() throws {
        let pair = BackToBackEmbeddedChannel()
        defer { XCTAssertNoThrow(try pair.finish()) }
        try pair.configureWithHarness(TestHarness())
        try pair.activate()
        try pair.interactInMemory()
        let first = try pair.createNewChannel()
        try pair.interactInMemory()
        let second = try pair.createNewChannel()
        try pair.interactInMemory()
        XCTAssertEqual(pair.activeServerChannels.count, 2)
        let flush = AbortChildOnParentFlush(child: second)
        try pair.client.pipeline.syncOperations.addHandler(flush, position: .first)
        let terminal = NIOLoopBoundBox(0, eventLoop: first.eventLoop)
        for child in [first, second] {
            child.closeFuture.whenFailure { error in
                XCTAssertEqual((error as? NIOSSHError)?.type, .channelAborted)
                terminal.value += 1
            }
        }
        first.triggerUserOutboundEvent(SSHChannelAbortEvent(), promise: nil)
        // No network delivery, child write or readComplete may trigger B's
        // retry. Only the queued drain/cleanup tasks can make progress.
        pair.run()
        XCTAssertTrue(flush.fired.value)
        XCTAssertEqual(terminal.value, 2)
        XCTAssertEqual(pair.activeServerChannels.count, 2)
        let firstClose = try XCTUnwrap(pair.client.readOutbound(as: IOData.self))
        let secondClose = try XCTUnwrap(pair.client.readOutbound(as: IOData.self))
        XCTAssertNil(try pair.client.readOutbound(as: IOData.self))
        try pair.server.writeInbound(firstClose)
        try pair.server.writeInbound(secondClose)
        try pair.interactInMemory()
        XCTAssertTrue(pair.activeServerChannels.isEmpty)
        // Both original reservations must release after the real peer ACKs;
        // admit the full fixed budget without evicting/reusing held IDs.
        for _ in 0..<Constants.maximumChannelReservations {
            _ = try pair.createNewChannel()
        }
        try pair.interactInMemory()
        XCTAssertEqual(pair.activeServerChannels.count, Constants.maximumChannelReservations)
        XCTAssertTrue(pair.client.isActive)
        XCTAssertTrue(pair.server.isActive)
    }
}
