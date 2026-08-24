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

/// The algorithms this build of NIOSSH will offer during negotiation,
/// exposed so that clients can *report* their transport security from the
/// engine's real configuration instead of a hand-written list that can
/// drift from it.
public enum NIOSSHSupportedAlgorithms {
    /// Key exchange algorithm names, in the preference order used during
    /// negotiation.
    public static var keyExchangeAlgorithms: [String] {
        SSHKeyExchangeStateMachine.supportedKeyExchangeAlgorithms.map(String.init)
    }
}
