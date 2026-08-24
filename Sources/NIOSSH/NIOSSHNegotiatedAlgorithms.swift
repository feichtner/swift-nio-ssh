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

/// The algorithms a connection actually negotiated during key exchange —
/// as opposed to ``NIOSSHSupportedAlgorithms``, which is what this build
/// can offer. Exposed so clients can show users what is really protecting
/// the session in front of them.
public struct NIOSSHNegotiatedAlgorithms: Hashable, Sendable {
    /// The negotiated key exchange algorithm, e.g. `sntrup761x25519-sha512`.
    public var keyExchange: String

    /// The negotiated server host key algorithm, e.g. `ssh-ed25519`.
    public var hostKey: String

    /// The negotiated cipher, e.g. `aes256-gcm@openssh.com`.
    public var cipher: String
}
