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

// FeTerm patch (feterm-patches): external-signer hook.
//
// Upstream NIOSSHPrivateKey is a closed enum over concrete swift-crypto key
// types, which cannot express keys whose material is unavailable by design:
// FIDO2 security keys, Keychain SecKeys, PIV slots. This protocol lets such a
// key participate in client publickey user auth by producing pre-encoded wire
// blobs; NIOSSH carries the bytes verbatim and never learns the algorithm's
// framing (e.g. the sk- flags byte and signature counter).

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A client user-auth key whose signing happens outside NIOSSH.
///
/// Conformers produce *complete* SSH wire blobs:
///
/// - `publicKeyBlob` is the public-key blob as it appears in authorized_keys
///   (starting with `string(algorithmName)`).
/// - `sshSignature(forPayload:)` returns the complete signature blob
///   (`string(sig-algo-name)` followed by the algorithm-specific payload).
///
/// `sshSignature(forPayload:)` is called on the connection's event loop and
/// may block on user interaction (a security-key touch, biometrics). Callers
/// that use such keys should give each connection a private event loop so the
/// block cannot stall other connections' I/O.
///
/// Custom keys support client user authentication only: they cannot serve as
/// host keys, and NIOSSH cannot verify their signatures (a server does that).
public protocol NIOSSHCustomPrivateKey: Sendable {
    /// The SSH algorithm name, e.g. `"sk-ssh-ed25519@openssh.com"`.
    var algorithmName: String { get }

    /// The complete public-key wire blob, starting with
    /// `string(algorithmName)`.
    var publicKeyBlob: Data { get }

    /// Returns the complete SSH signature blob over `payload` (the SSH
    /// user-auth signable payload bytes). May block for user interaction.
    func sshSignature(forPayload payload: Data) throws -> Data
}
