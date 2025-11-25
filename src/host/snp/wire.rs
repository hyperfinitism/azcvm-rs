// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
use crate::types::snp::VcekChain;

use serde::{Deserialize, Serialize};
use x509_parser::pem::{Pem, parse_x509_pem};

/// Response body of the AMD certificates endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SevSnpCertResponse {
    /// Cache-Control returned by service (optional)
    #[serde(rename = "cacheControl")]
    pub cache_control: Option<String>,

    /// VCEK leaf certificate (PEM)
    #[serde(rename = "vcekCert")]
    pub vcek_cert: String,

    /// Trusted-computing-base measurement
    #[serde(rename = "tcbm")]
    pub tcbm: String,

    /// Concatenated ASK+ARK certificate chain (PEM)
    #[serde(rename = "certificateChain")]
    pub certificate_chain: String,
}

impl SevSnpCertResponse {
    pub fn vcek_chain(&self) -> Result<VcekChain, Error> {
        // Parse VCEK PEM
        let (_rem, vcek) = parse_x509_pem(self.vcek_cert.as_bytes())
            .map_err(|e| Error::ValidationError(format!("failed to parse VCEK PEM: {:?}", e)))?;

        // Parse ASK + ARK concatenated PEMs
        let mut ask_ark = Pem::iter_from_buffer(self.certificate_chain.as_bytes());
        let ask = ask_ark
            .next()
            .ok_or_else(|| Error::ValidationError("missing ASK PEM block".to_string()))?
            .map_err(|e| Error::ValidationError(format!("failed to parse ASK PEM: {}", e)))?;
        let ark = ask_ark
            .next()
            .ok_or_else(|| Error::ValidationError("missing ARK PEM block".to_string()))?
            .map_err(|e| Error::ValidationError(format!("failed to parse ARK PEM: {}", e)))?;

        Ok(VcekChain { vcek, ask, ark })
    }
}
