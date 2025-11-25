// SPDX-License-Identifier: Apache-2.0

use crate::host::urls::HOST_BASE_URL;

use once_cell::sync::Lazy;
use url::Url;

/// Host's TD Quote Generation Service URL: http://169.254.169.254/acc/tdquote
pub(crate) static HOST_TDQUOTE_URL: Lazy<Url> =
    Lazy::new(|| HOST_BASE_URL.join("acc/tdquote").unwrap());
