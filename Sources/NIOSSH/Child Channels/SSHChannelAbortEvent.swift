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

/// Immediately terminate one dedicated SSH child locally without waiting for
/// the peer's CLOSE. Send with `Channel.triggerUserOutboundEvent`.
///
/// Its promise and `closeFuture` complete after local handlers are removed,
/// failing with `NIOSSHError.ErrorType.channelAborted`. The parent and siblings
/// are preserved. A protocol reservation remains until the peer completes its
/// open/close handshake; this is not remote-process termination or rollback.
/// Repeated aborts follow the child's original terminal result.
public struct SSHChannelAbortEvent: Sendable {
    public init() {}
}
