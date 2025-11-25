// SPDX-License-Identifier: Apache-2.0

use x509_parser::pem::Pem;

/// Parsed VCEK and ASK+ARK certificates as PEM blocks
#[derive(Debug)]
pub struct VcekChain {
    /// VCEK certificate
    pub vcek: Pem,
    /// ASK certificate
    pub ask: Pem,
    /// ARK certificate
    pub ark: Pem,
}
