// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct TdQuoteRequest {
    #[serde(rename = "report")]
    report_b64url: String,
}

impl TdQuoteRequest {
    pub fn from_bytes(td_report: &[u8]) -> Self {
        TdQuoteRequest {
            report_b64url: URL_SAFE_NO_PAD.encode(td_report),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TdQuoteResponse {
    #[serde(rename = "quote")]
    quote_b64url: String,
}

impl TdQuoteResponse {
    pub fn quote_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(URL_SAFE_NO_PAD.decode(&self.quote_b64url)?)
    }
}
