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

/// The `sntrup761x25519-sha512` hybrid post-quantum key exchange
/// (draft-josefsson-ntruprime-ssh; OpenSSH's default since 9.0 as
/// `sntrup761x25519-sha512@openssh.com`).
///
/// A hybrid KEM: the client sends a Streamlined NTRU Prime 761 public key
/// and an X25519 public key concatenated; the server replies with an
/// sntrup761 ciphertext and its own X25519 public key concatenated. The
/// shared secret is `K = SHA-512(sntrup761_key ‖ x25519_secret)`, so a
/// break of either primitive alone recovers nothing. The session stays
/// secure against an adversary recording traffic today to decrypt with a
/// quantum computer later — as long as sntrup761 holds — while X25519
/// guards against sntrup761 turning out to be weaker than believed.
///
/// This deliberately does NOT conform to `ECDHCompatiblePrivateKey`: a KEM
/// is not a Diffie-Hellman (the server encapsulates rather than agreeing),
/// and the draft requires K to be hashed as an SSH `string` where classical
/// ECDH hashes it as an `mpint`. It implements the type-erased
/// `EllipticCurveKeyExchangeProtocol` directly, whose message shapes carry
/// opaque byte blobs and fit a KEM unchanged.
struct SNTRUP761X25519KeyExchange: EllipticCurveKeyExchangeProtocol {
    private var previousSessionIdentifier: ByteBuffer?
    private var ourRole: SSHConnectionRole

    /// The client's sntrup761 keypair. Only the client has one; the server
    /// encapsulates against the client's public key.
    private var sntrupPublicKey: [UInt8]
    private var sntrupSecretKey: [UInt8]
    private var x25519Key: Curve25519.KeyAgreement.PrivateKey

    static let sntrupPublicKeyBytes = Int(crypto_kem_sntrup761_PUBLICKEYBYTES)
    static let sntrupSecretKeyBytes = Int(crypto_kem_sntrup761_SECRETKEYBYTES)
    static let sntrupCiphertextBytes = Int(crypto_kem_sntrup761_CIPHERTEXTBYTES)
    static let sntrupSharedKeyBytes = Int(crypto_kem_sntrup761_BYTES)
    static let x25519PublicKeyBytes = 32

    /// Client public value `Q_C`: sntrup761 public key ‖ X25519 public key.
    static let clientPublicValueBytes = sntrupPublicKeyBytes + x25519PublicKeyBytes
    /// Server public value `Q_S`: sntrup761 ciphertext ‖ X25519 public key.
    static let serverPublicValueBytes = sntrupCiphertextBytes + x25519PublicKeyBytes

    static let keyExchangeAlgorithmNames: [Substring] = [
        "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
    ]

    init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?) {
        self.ourRole = ourRole
        self.previousSessionIdentifier = previousSessionIdentifier
        self.x25519Key = Curve25519.KeyAgreement.PrivateKey()

        switch ourRole {
        case .client:
            var publicKey = [UInt8](repeating: 0, count: Self.sntrupPublicKeyBytes)
            var secretKey = [UInt8](repeating: 0, count: Self.sntrupSecretKeyBytes)
            publicKey.withUnsafeMutableBufferPointer { pk in
                secretKey.withUnsafeMutableBufferPointer { sk in
                    _ = crypto_kem_sntrup761_keypair(pk.baseAddress, sk.baseAddress)
                }
            }
            self.sntrupPublicKey = publicKey
            self.sntrupSecretKey = secretKey
        case .server:
            self.sntrupPublicKey = []
            self.sntrupSecretKey = []
        }
    }

    func initiateKeyExchangeClientSide(allocator: ByteBufferAllocator) -> SSHMessage.KeyExchangeECDHInitMessage {
        precondition(self.ourRole.isClient, "Only clients may initiate the client side key exchange!")

        var buffer = allocator.buffer(capacity: Self.clientPublicValueBytes)
        buffer.writeBytes(self.sntrupPublicKey)
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
            let clientSntrupKey = clientValue.readBytes(length: Self.sntrupPublicKeyBytes),
            let clientX25519Bytes = clientValue.readBytes(length: Self.x25519PublicKeyBytes)
        else {
            throw NIOSSHError.invalidSSHMessage(
                reason: "sntrup761x25519 client public value must be exactly \(Self.clientPublicValueBytes) bytes"
            )
        }

        // Encapsulate against the client's sntrup761 key.
        var ciphertext = [UInt8](repeating: 0, count: Self.sntrupCiphertextBytes)
        var sntrupKey = [UInt8](repeating: 0, count: Self.sntrupSharedKeyBytes)
        defer { sntrupKey.resetBytes(in: sntrupKey.indices) }
        ciphertext.withUnsafeMutableBufferPointer { ct in
            sntrupKey.withUnsafeMutableBufferPointer { key in
                clientSntrupKey.withUnsafeBufferPointer { pk in
                    _ = crypto_kem_sntrup761_enc(ct.baseAddress, key.baseAddress, pk.baseAddress)
                }
            }
        }

        let clientX25519Key = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: clientX25519Bytes)
        let x25519Secret = try self.x25519Key.generatedSharedSecret(with: clientX25519Key)

        var sharedSecret = Self.deriveSharedSecret(sntrupKey: sntrupKey, x25519Secret: x25519Secret)
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
            let ciphertext = serverValue.readBytes(length: Self.sntrupCiphertextBytes),
            let serverX25519Bytes = serverValue.readBytes(length: Self.x25519PublicKeyBytes)
        else {
            throw NIOSSHError.invalidSSHMessage(
                reason: "sntrup761x25519 server public value must be exactly \(Self.serverPublicValueBytes) bytes"
            )
        }

        // Decapsulate. sntrup761 is an implicit-rejection KEM: a corrupted
        // ciphertext does not error, it yields a *different* key, and the
        // handshake then dies verifying the server's exchange-hash
        // signature below. That is the failure mode the design intends.
        var sntrupKey = [UInt8](repeating: 0, count: Self.sntrupSharedKeyBytes)
        defer { sntrupKey.resetBytes(in: sntrupKey.indices) }
        sntrupKey.withUnsafeMutableBufferPointer { key in
            ciphertext.withUnsafeBufferPointer { ct in
                self.sntrupSecretKey.withUnsafeBufferPointer { sk in
                    _ = crypto_kem_sntrup761_dec(key.baseAddress, ct.baseAddress, sk.baseAddress)
                }
            }
        }
        self.sntrupSecretKey.resetBytes(in: self.sntrupSecretKey.indices)

        let serverX25519Key = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverX25519Bytes)
        let x25519Secret = try self.x25519Key.generatedSharedSecret(with: serverX25519Key)

        var sharedSecret = Self.deriveSharedSecret(sntrupKey: sntrupKey, x25519Secret: x25519Secret)
        defer { sharedSecret.resetBytes(in: sharedSecret.indices) }

        var clientValue = allocator.buffer(capacity: Self.clientPublicValueBytes)
        clientValue.writeBytes(self.sntrupPublicKey)
        clientValue.writeContiguousBytes(self.x25519Key.publicKey.rawRepresentation)

        let result = self.finalize(
            clientPublicValue: clientValue,
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

    /// `K = SHA-512(sntrup761 key ‖ X25519 shared secret)`, both 32 bytes.
    private static func deriveSharedSecret(sntrupKey: [UInt8], x25519Secret: SharedSecret) -> [UInt8] {
        var hasher = SHA512()
        sntrupKey.withUnsafeBufferPointer { hasher.update(bufferPointer: UnsafeRawBufferPointer($0)) }
        x25519Secret.withUnsafeBytes { hasher.update(bufferPointer: $0) }
        return Array(hasher.finalize())
    }

    private struct FinalizedResult {
        var sessionID: ByteBuffer
        var exchangeHash: SHA512.Digest
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
        // section 4), with one deviation the draft mandates: "Instead of
        // encoding the shared secret K as 'mpint', it MUST be encoded as
        // 'string'." That applies everywhere K enters a hash, including the
        // key derivation below.
        initialExchangeBytes.writeCompositeSSHString {
            $0.writeSSHHostKey(serverHostKey)
        }
        var clientValue = clientPublicValue
        var serverValue = serverPublicValue
        initialExchangeBytes.writeSSHString(&clientValue)
        initialExchangeBytes.writeSSHString(&serverValue)

        var exchangeHasher = SHA512()
        initialExchangeBytes.withUnsafeReadableBytes { exchangeHasher.update(bufferPointer: $0) }
        exchangeHasher.updateAsSSHString(sharedSecret)
        let exchangeHash = exchangeHasher.finalize()

        let sessionID: ByteBuffer
        if let previousSessionIdentifier = self.previousSessionIdentifier {
            sessionID = previousSessionIdentifier
        } else {
            var hashBytes = allocator.buffer(capacity: SHA512.Digest.byteCount)
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
        exchangeHash: SHA512.Digest,
        sessionID: ByteBuffer,
        expectedKeySizes: ExpectedKeySizes
    ) -> NIOSSHSessionKeys {
        // RFC 4253 section 7.2, with K encoded as a string (see above).
        var baseHasher = SHA512()
        baseHasher.updateAsSSHString(sharedSecret)
        exchangeHash.withUnsafeBytes { baseHasher.update(bufferPointer: $0) }

        func deriveKey(_ discriminator: UInt8, _ size: Int) -> [UInt8] {
            assert(size <= SHA512.Digest.byteCount)
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
    /// and a set top bit are hashed as-is, per the sntrup761x25519 draft.
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
