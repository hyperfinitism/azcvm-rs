// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
mod wire;
use wire::{TdQuoteRequest, TdQuoteResponse};
mod urls;
use urls::HOST_TDQUOTE_URL;

/// Get a TD Quote from the host service by sending the raw 1024-byte TD Report.
/// Returns the quote bytes on success.
pub fn get_td_quote_from_host(td_report: &[u8]) -> Result<Vec<u8>, Error> {
    let url = HOST_TDQUOTE_URL.clone();

    let body = TdQuoteRequest::from_bytes(td_report);

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let resp: TdQuoteResponse = client
        .post(url.as_str())
        .json(&body)
        .send()?
        .error_for_status()?
        .json()?;

    resp.quote_bytes()
}
