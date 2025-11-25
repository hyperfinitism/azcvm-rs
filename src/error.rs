// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid size: expected {expected} bytes, got {actual} bytes")]
    InvalidSize { expected: usize, actual: usize },

    #[error("unknown report type: {0}")]
    UnknownReportType(u32),

    #[error("unknown hash type: {0}")]
    UnknownHashType(u32),

    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error("UTF-8 error: {0}")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("validation error: {0}")]
    ValidationError(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),

    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
}
