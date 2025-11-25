// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
use crate::types::snp::VcekChain;
mod wire;
use wire::SevSnpCertResponse;
mod urls;
use urls::HOST_AMD_CERTS_URL;

/// Fetch and parse VCEK and ASK+ARK chain from the host's IMDS/THIM inside the guest.
pub fn get_vcek_chain_from_host() -> Result<VcekChain, Error> {
    let url = HOST_AMD_CERTS_URL.clone();

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let resp = client
        .get(url.as_str())
        .header("Metadata", "true")
        .send()?
        .error_for_status()?;

    // Unmarshal the raw response JSON
    let resp_parsed: SevSnpCertResponse = resp.json()?;

    resp_parsed.vcek_chain()
}
