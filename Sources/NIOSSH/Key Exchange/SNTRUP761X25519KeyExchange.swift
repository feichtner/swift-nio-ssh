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
import NIOFoundationCompat

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The hybrid post-quantum key exchanges: `mlkem768x25519-sha256`
/// (draft-kampanakis-curdle-ssh-pq-ke; OpenSSH's default since 9.9) and
/// `sntrup761x25519-sha512` (draft-josefsson-ntruprime-ssh; OpenSSH's
/// default 9.0–9.8, offered since 8.5).
///
/// Both follow the same shape, differing only in the KEM and the hash:
/// the client sends its KEM public key and an X25519 public key
/// concatenated; the server replies with a KEM ciphertext and its own
/// X25519 public key concatenated; the shared secret is
/// `K = HASH(kem_key ‖ x25519_secret)`, so a break of either primitive
/// alone recovers nothing. The session stays secure against an adversary
/// recording traffic today to decrypt with a quantum computer later — as
/// long as the lattice KEM holds — while X25519 guards against the KEM
/// turning out to be weaker than believed.
///
/// This deliberately does NOT conform to `ECDHCompatiblePrivateKey`: a KEM
/// is not a Diffie-Hellman (the server encapsulates rather than agreeing),
/// and both drafts require K to be hashed as an SSH `string` where
/// classical ECDH hashes it as an `mpint`. It implements the type-erased
/// `EllipticCurveKeyExchangeProtocol` directly, whose message shapes carry
/// opaque byte blobs and fit a KEM unchanged.
protocol HybridKEMProvider {
    associatedtype Hasher: HashFunction
    /// A client's decapsulation capability, kept opaque: raw bytes for the
    /// C sntrup761, a CryptoKit object for ML-KEM.
    associatedtype SecretKey

    static var publicKeyBytes: Int { get }
    static var ciphertextBytes: Int { get }
    static var keyExchangeAlgorithmNames: [Substring] { get }

    static func keypair() -> (publicKey: [UInt8], secretKey: SecretKey)
    /// Server side: encapsulate a fresh shared key to the client's public key.
    static func encapsulate(to publicKey: [UInt8]) throws -> (ciphertext: [UInt8], key: [UInt8])
    /// Client side: recover the shared key from the server's ciphertext.
    static func decapsulate(_ ciphertext: [UInt8], with secretKey: inout SecretKey) throws -> [UInt8]
}

enum SNTRUP761: HybridKEMProvider {
    typealias Hasher = SHA512
    typealias SecretKey = [UInt8]

    static let publicKeyBytes = Int(crypto_kem_sntrup761_PUBLICKEYBYTES)
    static let ciphertextBytes = Int(crypto_kem_sntrup761_CIPHERTEXTBYTES)
    static let sharedKeyBytes = Int(crypto_kem_sntrup761_BYTES)
    static let secretKeyBytes = Int(crypto_kem_sntrup761_SECRETKEYBYTES)

    static let keyExchangeAlgorithmNames: [Substring] = [
        "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
    ]

    static func keypair() -> (publicKey: [UInt8], secretKey: [UInt8]) {
        var publicKey = [UInt8](repeating: 0, count: Self.publicKeyBytes)
        var secretKey = [UInt8](repeating: 0, count: Self.secretKeyBytes)
        publicKey.withUnsafeMutableBufferPointer { pk in
            secretKey.withUnsafeMutableBufferPointer { sk in
                _ = crypto_kem_sntrup761_keypair(pk.baseAddress, sk.baseAddress)
            }
        }
        return (publicKey, secretKey)
    }

    static func encapsulate(to publicKey: [UInt8]) throws -> (ciphertext: [UInt8], key: [UInt8]) {
        var ciphertext = [UInt8](repeating: 0, count: Self.ciphertextBytes)
        var key = [UInt8](repeating: 0, count: Self.sharedKeyBytes)
        ciphertext.withUnsafeMutableBufferPointer { ct in
            key.withUnsafeMutableBufferPointer { k in
                publicKey.withUnsafeBufferPointer { pk in
                    _ = crypto_kem_sntrup761_enc(ct.baseAddress, k.baseAddress, pk.baseAddress)
                }
            }
        }
        return (ciphertext, key)
    }

    /// sntrup761 is an implicit-rejection KEM: a corrupted ciphertext does
    /// not error, it yields a *different* key, and the handshake then dies
    /// verifying the server's exchange-hash signature. That is the failure
    /// mode the design intends.
    static func decapsulate(_ ciphertext: [UInt8], with secretKey: inout [UInt8]) throws -> [UInt8] {
        var key = [UInt8](repeating: 0, count: Self.sharedKeyBytes)
        key.withUnsafeMutableBufferPointer { k in
            ciphertext.withUnsafeBufferPointer { ct in
                secretKey.withUnsafeBufferPointer { sk in
                    _ = crypto_kem_sntrup761_dec(k.baseAddress, ct.baseAddress, sk.baseAddress)
                }
            }
        }
        secretKey.resetBytes(in: secretKey.indices)
        return key
    }
}

/// swift-crypto's ML-KEM comes from CryptoKit on Darwin, which gates it
/// on the 26.0 OS generation; on Linux it is BoringSSL-backed and always
/// present (availability checks are no-ops there).
@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
enum MLKEM768: HybridKEMProvider {
    typealias Hasher = SHA256
    typealias SecretKey = Crypto.MLKEM768.PrivateKey

    static let publicKeyBytes = 1184
    static let ciphertextBytes = 1088

    static let keyExchangeAlgorithmNames: [Substring] = ["mlkem768x25519-sha256"]

    static func keypair() -> (publicKey: [UInt8], secretKey: Crypto.MLKEM768.PrivateKey) {
        // Key generation only throws on entropy failure, the same condition
        // the sntrup761 shim answers with abort(): proceeding without
        // randomness would be far worse than crashing.
        let key = try! Crypto.MLKEM768.PrivateKey()
        return (Array(key.publicKey.rawRepresentation), key)
    }

    static func encapsulate(to publicKey: [UInt8]) throws -> (ciphertext: [UInt8], key: [UInt8]) {
        let clientKey = try Crypto.MLKEM768.PublicKey(rawRepresentation: publicKey)
        let result = try clientKey.encapsulate()
        let key = result.sharedSecret.withUnsafeBytes { Array($0) }
        return (Array(result.encapsulated), key)
    }

    /// ML-KEM is an implicit-rejection KEM like sntrup761: see above.
    /// Single use is the caller's job — it drops its reference before
    /// decapsulating.
    static func decapsulate(
        _ ciphertext: [UInt8], with secretKey: inout Crypto.MLKEM768.PrivateKey
    ) throws -> [UInt8] {
        let shared = try secretKey.decapsulate(Data(ciphertext))
        return shared.withUnsafeBytes { Array($0) }
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
typealias MLKEM768X25519KeyExchange = HybridKEMX25519KeyExchange<MLKEM768>
typealias SNTRUP761X25519KeyExchange = HybridKEMX25519KeyExchange<SNTRUP761>

struct HybridKEMX25519KeyExchange<KEM: HybridKEMProvider>: EllipticCurveKeyExchangeProtocol {
    private var previousSessionIdentifier: ByteBuffer?
    private var ourRole: SSHConnectionRole

    /// The client's KEM keypair. Only the client has one; the server
    /// encapsulates against the client's public key.
    private var kemPublicKey: [UInt8]
    private var kemSecretKey: KEM.SecretKey?
    private var x25519Key: Curve25519.KeyAgreement.PrivateKey

    static var x25519PublicKeyBytes: Int { 32 }

    /// Client public value `Q_C`: KEM public key ‖ X25519 public key.
    static var clientPublicValueBytes: Int { KEM.publicKeyBytes + x25519PublicKeyBytes }
    /// Server public value `Q_S`: KEM ciphertext ‖ X25519 public key.
    static var serverPublicValueBytes: Int { KEM.ciphertextBytes + x25519PublicKeyBytes }

    static var keyExchangeAlgorithmNames: [Substring] { KEM.keyExchangeAlgorithmNames }

    init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?) {
        self.ourRole = ourRole
        self.previousSessionIdentifier = previousSessionIdentifier
        self.x25519Key = Curve25519.KeyAgreement.PrivateKey()

        switch ourRole {
        case .client:
            let (publicKey, secretKey) = KEM.keypair()
            self.kemPublicKey = publicKey
            self.kemSecretKey = secretKey
        case .server:
            self.kemPublicKey = []
            self.kemSecretKey = nil
        }
    }

    func initiateKeyExchangeClientSide(allocator: ByteBufferAllocator) -> SSHMessage.KeyExchangeECDHInitMessage {
        precondition(self.ourRole.isClient, "Only clients may initiate the client side key exchange!")

        var buffer = allocator.buffer(capacity: Self.clientPublicValueBytes)
        buffer.writeBytes(self.kemPublicKey)
        buffer.writeContiguousBytes(self.x25519Key.publicKey.rawRepresentation)
        return .init(publicKey: buffer)
    }

    mutating func completeKeyExchangeServerSide(
        clientKeyExchangeMessage message: SSHMessage.KeyExchangeECDHInitMessage,
        serverHostKey: NIOSSHPrivateKey,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> (KeyExchangeResult, SSHMessage.KeyExchangeECDHReplyMessage) {
        precondition(self.ourRole.isServer, "Only servers may receive a client key exchange packet!")

        var clientValue = message.publicKey
        guard clientValue.readableBytes == Self.clientPublicValueBytes,
            let clientKEMKey = clientValue.readBytes(length: KEM.publicKeyBytes),
            let clientX25519Bytes = clientValue.readBytes(length: Self.x25519PublicKeyBytes)
        else {
            throw NIOSSHError.invalidSSHMessage(
                reason: "hybrid KEM client public value must be exactly \(Self.clientPublicValueBytes) bytes"
            )
        }

        let (ciphertext, kemKey) = try KEM.encapsulate(to: clientKEMKey)
        var kemKeyBytes = kemKey
        defer { kemKeyBytes.resetBytes(in: kemKeyBytes.indices) }

        let clientX25519Key = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: clientX25519Bytes)
        let x25519Secret = try self.x25519Key.generatedSharedSecret(with: clientX25519Key)

        var sharedSecret = Self.deriveSharedSecret(kemKey: kemKeyBytes, x25519Secret: x25519Secret)
        defer { sharedSecret.resetBytes(in: sharedSecret.indices) }

        var serverValue = allocator.buffer(capacity: Self.serverPublicValueBytes)
        serverValue.writeBytes(ciphertext)
        serverValue.writeContiguousBytes(self.x25519Key.publicKey.rawRepresentation)

        let result = self.finalize(
            clientPublicValue: message.publicKey,
            serverPublicValue: serverValue,
            sharedSecret: sharedSecret,
            initialExchangeBytes: &initialExchangeBytes,
            serverHostKey: serverHostKey.publicKey,
            allocator: allocator,
            expectedKeySizes: expectedKeySizes
        )

        let exchangeHashSignature = try serverHostKey.sign(digest: result.exchangeHash)
        let responseMessage = SSHMessage.KeyExchangeECDHReplyMessage(
            hostKey: serverHostKey.publicKey,
            publicKey: serverValue,
            signature: exchangeHashSignature
        )

        return (KeyExchangeResult(sessionID: result.sessionID, keys: result.keys), responseMessage)
    }

    mutating func receiveServerKeyExchangePayload(
        serverKeyExchangeMessage message: SSHMessage.KeyExchangeECDHReplyMessage,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> KeyExchangeResult {
        precondition(self.ourRole.isClient, "Only clients may receive a server key exchange packet!")

        var serverValue = message.publicKey
        guard serverValue.readableBytes == Self.serverPublicValueBytes,
            let ciphertext = serverValue.readBytes(length: KEM.ciphertextBytes),
            let serverX25519Bytes = serverValue.readBytes(length: Self.x25519PublicKeyBytes)
        else {
            throw NIOSSHError.invalidSSHMessage(
                reason: "hybrid KEM server public value must be exactly \(Self.serverPublicValueBytes) bytes"
            )
        }

        guard var secretKey = self.kemSecretKey else {
            throw NIOSSHError.invalidSSHMessage(reason: "hybrid KEM reply without a pending exchange")
        }
        self.kemSecretKey = nil
        var kemKeyBytes = try KEM.decapsulate(ciphertext, with: &secretKey)
        defer { kemKeyBytes.resetBytes(in: kemKeyBytes.indices) }

        let serverX25519Key = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverX25519Bytes)
        let x25519Secret = try self.x25519Key.generatedSharedSecret(with: serverX25519Key)

        var sharedSecret = Self.deriveSharedSecret(kemKey: kemKeyBytes, x25519Secret: x25519Secret)
        defer { sharedSecret.resetBytes(in: sharedSecret.indices) }

        let result = self.finalize(
            clientPublicValue: {
                var clientValue = allocator.buffer(capacity: Self.clientPublicValueBytes)
                clientValue.writeBytes(self.kemPublicKey)
                clientValue.writeContiguousBytes(self.x25519Key.publicKey.rawRepresentation)
                return clientValue
            }(),
            serverPublicValue: message.publicKey,
            sharedSecret: sharedSecret,
            initialExchangeBytes: &initialExchangeBytes,
            serverHostKey: message.hostKey,
            allocator: allocator,
            expectedKeySizes: expectedKeySizes
        )

        guard message.hostKey.isValidSignature(message.signature, for: result.exchangeHash) else {
            throw NIOSSHError.invalidExchangeHashSignature
        }

        return KeyExchangeResult(sessionID: result.sessionID, keys: result.keys)
    }

    /// `K = HASH(KEM key ‖ X25519 shared secret)` — the hybrid combiner.
    private static func deriveSharedSecret(kemKey: [UInt8], x25519Secret: SharedSecret) -> [UInt8] {
        var hasher = KEM.Hasher()
        kemKey.withUnsafeBufferPointer { hasher.update(bufferPointer: UnsafeRawBufferPointer($0)) }
        x25519Secret.withUnsafeBytes { hasher.update(bufferPointer: $0) }
        return Array(hasher.finalize())
    }

    private struct FinalizedResult {
        var sessionID: ByteBuffer
        var exchangeHash: KEM.Hasher.Digest
        var keys: NIOSSHSessionKeys
    }

    private func finalize(
        clientPublicValue: ByteBuffer,
        serverPublicValue: ByteBuffer,
        sharedSecret: [UInt8],
        initialExchangeBytes: inout ByteBuffer,
        serverHostKey: NIOSSHPublicKey,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) -> FinalizedResult {
        // The exchange hash has the same layout as classical ECDH (RFC 5656
        // section 4), with one deviation both drafts mandate: the shared
        // secret K is encoded as `string`, not `mpint` — everywhere K
        // enters a hash, including the key derivation below.
        initialExchangeBytes.writeCompositeSSHString {
            $0.writeSSHHostKey(serverHostKey)
        }
        var clientValue = clientPublicValue
        var serverValue = serverPublicValue
        initialExchangeBytes.writeSSHString(&clientValue)
        initialExchangeBytes.writeSSHString(&serverValue)

        var exchangeHasher = KEM.Hasher()
        initialExchangeBytes.withUnsafeReadableBytes { exchangeHasher.update(bufferPointer: $0) }
        exchangeHasher.updateAsSSHString(sharedSecret)
        let exchangeHash = exchangeHasher.finalize()

        let sessionID: ByteBuffer
        if let previousSessionIdentifier = self.previousSessionIdentifier {
            sessionID = previousSessionIdentifier
        } else {
            var hashBytes = allocator.buffer(capacity: KEM.Hasher.Digest.byteCount)
            hashBytes.writeContiguousBytes(exchangeHash)
            sessionID = hashBytes
        }

        let keys = self.generateKeys(
            sharedSecret: sharedSecret,
            exchangeHash: exchangeHash,
            sessionID: sessionID,
            expectedKeySizes: expectedKeySizes
        )

        return FinalizedResult(sessionID: sessionID, exchangeHash: exchangeHash, keys: keys)
    }

    private func generateKeys(
        sharedSecret: [UInt8],
        exchangeHash: KEM.Hasher.Digest,
        sessionID: ByteBuffer,
        expectedKeySizes: ExpectedKeySizes
    ) -> NIOSSHSessionKeys {
        // RFC 4253 section 7.2, with K encoded as a string (see above).
        var baseHasher = KEM.Hasher()
        baseHasher.updateAsSSHString(sharedSecret)
        exchangeHash.withUnsafeBytes { baseHasher.update(bufferPointer: $0) }

        func deriveKey(_ discriminator: UInt8, _ size: Int) -> [UInt8] {
            assert(size <= KEM.Hasher.Digest.byteCount)
            var hasher = baseHasher
            withUnsafeBytes(of: discriminator) { hasher.update(bufferPointer: $0) }
            hasher.update(data: sessionID.readableBytesView)
            return Array(hasher.finalize().prefix(size))
        }

        switch self.ourRole {
        case .client:
            return NIOSSHSessionKeys(
                initialInboundIV: deriveKey(UInt8(ascii: "B"), expectedKeySizes.ivSize),
                initialOutboundIV: deriveKey(UInt8(ascii: "A"), expectedKeySizes.ivSize),
                inboundEncryptionKey: SymmetricKey(data: deriveKey(UInt8(ascii: "D"), expectedKeySizes.encryptionKeySize)),
                outboundEncryptionKey: SymmetricKey(data: deriveKey(UInt8(ascii: "C"), expectedKeySizes.encryptionKeySize)),
                inboundMACKey: SymmetricKey(data: deriveKey(UInt8(ascii: "F"), expectedKeySizes.macKeySize)),
                outboundMACKey: SymmetricKey(data: deriveKey(UInt8(ascii: "E"), expectedKeySizes.macKeySize))
            )
        case .server:
            return NIOSSHSessionKeys(
                initialInboundIV: deriveKey(UInt8(ascii: "A"), expectedKeySizes.ivSize),
                initialOutboundIV: deriveKey(UInt8(ascii: "B"), expectedKeySizes.ivSize),
                inboundEncryptionKey: SymmetricKey(data: deriveKey(UInt8(ascii: "C"), expectedKeySizes.encryptionKeySize)),
                outboundEncryptionKey: SymmetricKey(data: deriveKey(UInt8(ascii: "D"), expectedKeySizes.encryptionKeySize)),
                inboundMACKey: SymmetricKey(data: deriveKey(UInt8(ascii: "E"), expectedKeySizes.macKeySize)),
                outboundMACKey: SymmetricKey(data: deriveKey(UInt8(ascii: "F"), expectedKeySizes.macKeySize))
            )
        }
    }
}

extension HashFunction {
    /// Hashes `bytes` as an SSH `string`: a 32-bit big-endian length,
    /// then the raw bytes. No mpint normalization — leading zero bytes
    /// and a set top bit are hashed as-is, per both hybrid KEX drafts.
    fileprivate mutating func updateAsSSHString(_ bytes: [UInt8]) {
        let length = UInt32(bytes.count).bigEndian
        withUnsafeBytes(of: length) { self.update(bufferPointer: $0) }
        bytes.withUnsafeBufferPointer { self.update(bufferPointer: UnsafeRawBufferPointer($0)) }
    }
}

extension [UInt8] {
    /// Best-effort zeroization of secret material once it is consumed.
    /// Swift arrays may have been copied by value in the meantime; this
    /// clears the buffer we hold, which is the strongest guarantee
    /// available without CryptoKit-style secure storage.
    fileprivate mutating func resetBytes(in range: Range<Int>) {
        self.withUnsafeMutableBufferPointer { buffer in
            guard let base = buffer.baseAddress, !range.isEmpty else { return }
            base.advanced(by: range.lowerBound)
                .update(repeating: 0, count: range.count)
        }
    }
}
