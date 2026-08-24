//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import CNIOSSHSNTRUP761
import Crypto
import NIOCore
import XCTest

@testable import NIOSSH

final class SNTRUP761X25519KeyExchangeTests: XCTestCase {
    private func keyExchangeAgreed(_ first: KeyExchangeResult, _ second: KeyExchangeResult) {
        XCTAssertEqual(first.sessionID, second.sessionID)
        XCTAssertEqual(first.keys.initialInboundIV, second.keys.initialOutboundIV)
        XCTAssertEqual(first.keys.initialOutboundIV, second.keys.initialInboundIV)
        XCTAssertEqual(first.keys.inboundEncryptionKey, second.keys.outboundEncryptionKey)
        XCTAssertEqual(first.keys.outboundEncryptionKey, second.keys.inboundEncryptionKey)
        XCTAssertEqual(first.keys.inboundMACKey, second.keys.outboundMACKey)
        XCTAssertEqual(first.keys.outboundMACKey, second.keys.inboundMACKey)
    }

    private func performHandshake(
        previousSessionIdentifier: ByteBuffer? = nil,
        serverHostKey: NIOSSHPrivateKey = NIOSSHPrivateKey(ed25519Key: .init()),
        corruptServerResponse: ((inout SSHMessage.KeyExchangeECDHReplyMessage) throws -> Void)? = nil
    ) throws -> (server: KeyExchangeResult, client: KeyExchangeResult) {
        var server = SNTRUP761X25519KeyExchange(
            ourRole: .server([serverHostKey]),
            previousSessionIdentifier: previousSessionIdentifier
        )
        var client = SNTRUP761X25519KeyExchange(
            ourRole: .client,
            previousSessionIdentifier: previousSessionIdentifier
        )

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 2048)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        var (serverKeys, serverResponse) = try server.completeKeyExchangeServerSide(
            clientKeyExchangeMessage: clientMessage,
            serverHostKey: serverHostKey,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: ByteBufferAllocator(),
            expectedKeySizes: AES256GCMOpenSSHTransportProtection.keySizes
        )

        initialExchangeBytes.clear()
        try corruptServerResponse?(&serverResponse)

        let clientKeys = try client.receiveServerKeyExchangePayload(
            serverKeyExchangeMessage: serverResponse,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: ByteBufferAllocator(),
            expectedKeySizes: AES256GCMOpenSSHTransportProtection.keySizes
        )

        return (serverKeys, clientKeys)
    }

    func testBasicSuccessfulKeyExchange() throws {
        let (serverKeys, clientKeys) = try self.performHandshake()
        self.keyExchangeAgreed(serverKeys, clientKeys)
    }

    func testKeyExchangeWithPreviousSession() throws {
        var previousSessionIdentifier = ByteBufferAllocator().buffer(capacity: 256)
        previousSessionIdentifier.writeBytes(0...255)
        let (serverKeys, clientKeys) = try self.performHandshake(
            previousSessionIdentifier: previousSessionIdentifier
        )
        self.keyExchangeAgreed(serverKeys, clientKeys)
        XCTAssertEqual(clientKeys.sessionID, previousSessionIdentifier)
    }

    func testKeyExchangeWithECDSAHostKey() throws {
        let (serverKeys, clientKeys) = try self.performHandshake(
            serverHostKey: NIOSSHPrivateKey(p256Key: .init())
        )
        self.keyExchangeAgreed(serverKeys, clientKeys)
    }

    func testWireSizesMatchTheDraft() throws {
        let client = SNTRUP761X25519KeyExchange(ourRole: .client, previousSessionIdentifier: nil)
        let message = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        XCTAssertEqual(message.publicKey.readableBytes, 1190)

        var server = SNTRUP761X25519KeyExchange(
            ourRole: .server([NIOSSHPrivateKey(ed25519Key: .init())]),
            previousSessionIdentifier: nil
        )
        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 2048)
        let (_, response) = try server.completeKeyExchangeServerSide(
            clientKeyExchangeMessage: message,
            serverHostKey: NIOSSHPrivateKey(ed25519Key: .init()),
            initialExchangeBytes: &initialExchangeBytes,
            allocator: ByteBufferAllocator(),
            expectedKeySizes: AES256GCMOpenSSHTransportProtection.keySizes
        )
        XCTAssertEqual(response.publicKey.readableBytes, 1071)
    }

    /// A tampered ciphertext must not error out of the KEM (implicit
    /// rejection yields a different key); it must surface as a failed
    /// exchange-hash signature check, exactly like classical ECDH tampering.
    func testTamperedCiphertextFailsSignatureValidation() throws {
        XCTAssertThrowsError(
            try self.performHandshake(corruptServerResponse: { response in
                var corrupted = ByteBufferAllocator().buffer(capacity: 1071)
                var original = response.publicKey
                let firstByte = original.readInteger(as: UInt8.self)!
                corrupted.writeInteger(firstByte ^ 0xFF)
                corrupted.writeBytes(original.readableBytesView)
                response.publicKey = corrupted
            })
        ) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidExchangeHashSignature)
        }
    }

    func testWrongLengthServerValueIsRejected() throws {
        XCTAssertThrowsError(
            try self.performHandshake(corruptServerResponse: { response in
                var truncated = response.publicKey
                truncated.moveWriterIndex(to: truncated.writerIndex - 1)
                response.publicKey = truncated
            })
        ) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidSSHMessage)
        }
    }

    func testForgedSignatureIsRejected() throws {
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())
        XCTAssertThrowsError(
            try self.performHandshake(
                serverHostKey: serverHostKey,
                corruptServerResponse: { response in
                    response.signature = try serverHostKey.sign(digest: SHA512.hash(data: [1, 2, 3]))
                }
            )
        ) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidExchangeHashSignature)
        }
    }

    /// The whole point of adding the algorithms: the hybrids must lead the
    /// preference list — ML-KEM first where the platform has it (matching
    /// OpenSSH >= 9.9's default order), sntrup761 right behind under both
    /// its IANA and its @openssh.com name.
    func testPostQuantumExchangesArePreferred() {
        var expected: [Substring] = []
        if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *) {
            expected.append("mlkem768x25519-sha256")
        }
        expected.append(contentsOf: ["sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com"])

        let algorithms = SSHKeyExchangeStateMachine.supportedKeyExchangeAlgorithms
        XCTAssertEqual(Array(algorithms.prefix(expected.count)), expected)
        XCTAssertEqual(
            NIOSSHSupportedAlgorithms.keyExchangeAlgorithms.prefix(expected.count),
            expected.map(String.init)[...]
        )
    }

    // MARK: The vendored C primitive

    func testSntrupRoundTrip() {
        var publicKey = [UInt8](repeating: 0, count: 1158)
        var secretKey = [UInt8](repeating: 0, count: 1763)
        XCTAssertEqual(crypto_kem_sntrup761_keypair(&publicKey, &secretKey), 0)

        var ciphertext = [UInt8](repeating: 0, count: 1039)
        var encapsulated = [UInt8](repeating: 0, count: 32)
        XCTAssertEqual(crypto_kem_sntrup761_enc(&ciphertext, &encapsulated, publicKey), 0)

        var decapsulated = [UInt8](repeating: 0, count: 32)
        XCTAssertEqual(crypto_kem_sntrup761_dec(&decapsulated, ciphertext, secretKey), 0)
        XCTAssertEqual(encapsulated, decapsulated)

        // Implicit rejection: flipping a ciphertext bit yields a DIFFERENT
        // key rather than an error.
        ciphertext[0] ^= 0x01
        var rejected = [UInt8](repeating: 0, count: 32)
        XCTAssertEqual(crypto_kem_sntrup761_dec(&rejected, ciphertext, secretKey), 0)
        XCTAssertNotEqual(rejected, decapsulated)
    }

    func testTwoKeypairsDiffer() {
        var pk1 = [UInt8](repeating: 0, count: 1158)
        var sk1 = [UInt8](repeating: 0, count: 1763)
        var pk2 = [UInt8](repeating: 0, count: 1158)
        var sk2 = [UInt8](repeating: 0, count: 1763)
        XCTAssertEqual(crypto_kem_sntrup761_keypair(&pk1, &sk1), 0)
        XCTAssertEqual(crypto_kem_sntrup761_keypair(&pk2, &sk2), 0)
        XCTAssertNotEqual(pk1, pk2)
    }

    /// The shim SHA-512 against the FIPS 180-4 / RFC 6234 known-answer
    /// vectors, plus a multi-block input checked against swift-crypto.
    /// Everything in the exchange trusts this hash, so it is pinned hard.
    func testShimSHA512KnownAnswers() {
        func sha512Hex(_ input: [UInt8]) -> String {
            var digest = [UInt8](repeating: 0, count: 64)
            XCTAssertEqual(crypto_hash_sha512(&digest, input, UInt64(input.count)), 0)
            return digest.map { String(format: "%02x", $0) }.joined()
        }

        XCTAssertEqual(
            sha512Hex(Array("abc".utf8)),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
        XCTAssertEqual(
            sha512Hex([]),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                + "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
        XCTAssertEqual(
            sha512Hex(Array("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".utf8)),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                + "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        )

        // Exercise every padding path (tail 111, 112, 127 bytes and a
        // >2-block input) against swift-crypto's SHA-512.
        for size in [111, 112, 127, 128, 129, 300, 1190] {
            let input = (0..<size).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 13) }
            var digest = [UInt8](repeating: 0, count: 64)
            XCTAssertEqual(crypto_hash_sha512(&digest, input, UInt64(input.count)), 0)
            XCTAssertEqual(digest, Array(SHA512.hash(data: input)), "size \(size)")
        }
    }
}

extension SSHConnectionRole {
    fileprivate static func server(_ hostKeys: [NIOSSHPrivateKey]) -> SSHConnectionRole {
        .server(SSHServerConfiguration(hostKeys: hostKeys, userAuthDelegate: DenyAllServerAuthDelegate()))
    }

    fileprivate static var client: SSHConnectionRole {
        .client(
            SSHClientConfiguration(
                userAuthDelegate: ExplodingAuthDelegate(),
                serverAuthDelegate: AcceptAllHostKeysDelegate()
            )
        )
    }
}

final class NegotiatedAlgorithmsTests: XCTestCase {
    /// The handler must report what the handshake really negotiated, and
    /// the value must survive past key exchange into the active connection
    /// (the states that drop the key exchange machine carry it forward).
    func testHandlerReportsNegotiatedAlgorithms() throws {
        let channel = BackToBackEmbeddedChannel()
        defer { try? channel.finish() }
        XCTAssertNoThrow(try channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())

        // Both in-memory peers are this build, so the shared first
        // preference must have won: ML-KEM where the platform has it,
        // sntrup761 otherwise.
        let expectedKex: String
        if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *) {
            expectedKex = "mlkem768x25519-sha256"
        } else {
            expectedKex = "sntrup761x25519-sha512"
        }
        for handler in [channel.clientSSHHandler, channel.serverSSHHandler] {
            let negotiated = try XCTUnwrap(try XCTUnwrap(handler).negotiatedAlgorithms)
            XCTAssertEqual(negotiated.keyExchange, expectedKex)
            XCTAssertEqual(negotiated.hostKey, "ssh-ed25519")
            XCTAssertFalse(negotiated.cipher.isEmpty)
        }
    }
}

/// The ML-KEM variant of the hybrid exchange, sharing the generic engine
/// with sntrup761 — these tests pin what differs: sizes, hash, and the
/// swift-crypto-backed KEM. Darwin needs the 26.0 OS generation for
/// CryptoKit's ML-KEM; Linux always has it via BoringSSL.
@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
final class MLKEM768X25519KeyExchangeTests: XCTestCase {
    private func performHandshake(
        corruptServerResponse: ((inout SSHMessage.KeyExchangeECDHReplyMessage) throws -> Void)? = nil
    ) throws -> (server: KeyExchangeResult, client: KeyExchangeResult) {
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())
        var server = MLKEM768X25519KeyExchange(
            ourRole: .server([serverHostKey]),
            previousSessionIdentifier: nil
        )
        var client = MLKEM768X25519KeyExchange(ourRole: .client, previousSessionIdentifier: nil)

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 2048)
        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        XCTAssertEqual(clientMessage.publicKey.readableBytes, 1216)

        var (serverKeys, serverResponse) = try server.completeKeyExchangeServerSide(
            clientKeyExchangeMessage: clientMessage,
            serverHostKey: serverHostKey,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: ByteBufferAllocator(),
            expectedKeySizes: AES256GCMOpenSSHTransportProtection.keySizes
        )
        XCTAssertEqual(serverResponse.publicKey.readableBytes, 1120)

        initialExchangeBytes.clear()
        try corruptServerResponse?(&serverResponse)

        let clientKeys = try client.receiveServerKeyExchangePayload(
            serverKeyExchangeMessage: serverResponse,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: ByteBufferAllocator(),
            expectedKeySizes: AES256GCMOpenSSHTransportProtection.keySizes
        )
        return (serverKeys, clientKeys)
    }

    func testBasicSuccessfulKeyExchange() throws {
        let (serverKeys, clientKeys) = try self.performHandshake()
        XCTAssertEqual(serverKeys.sessionID, clientKeys.sessionID)
        XCTAssertEqual(serverKeys.keys.inboundEncryptionKey, clientKeys.keys.outboundEncryptionKey)
        XCTAssertEqual(serverKeys.keys.outboundEncryptionKey, clientKeys.keys.inboundEncryptionKey)
    }

    func testTamperedCiphertextFailsSignatureValidation() throws {
        XCTAssertThrowsError(
            try self.performHandshake(corruptServerResponse: { response in
                var corrupted = ByteBufferAllocator().buffer(capacity: 1120)
                var original = response.publicKey
                let firstByte = original.readInteger(as: UInt8.self)!
                corrupted.writeInteger(firstByte ^ 0xFF)
                corrupted.writeBytes(original.readableBytesView)
                response.publicKey = corrupted
            })
        ) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidExchangeHashSignature)
        }
    }

    func testWrongLengthServerValueIsRejected() throws {
        XCTAssertThrowsError(
            try self.performHandshake(corruptServerResponse: { response in
                var truncated = response.publicKey
                truncated.moveWriterIndex(to: truncated.writerIndex - 1)
                response.publicKey = truncated
            })
        ) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidSSHMessage)
        }
    }
}
