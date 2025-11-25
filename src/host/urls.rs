// SPDX-License-Identifier: Apache-2.0

use once_cell::sync::Lazy;
use url::Url;

/// Link-local address to the host (shared between SEV-SNP / TDX VMs)
/// http://169.254.169.254
pub(crate) static HOST_BASE_URL: Lazy<Url> =
    Lazy::new(|| Url::parse("http://169.254.169.254").unwrap());

/// Azure Instance MetaData Service (IMDS)
/// http://169.254.169.254/metadata
pub(crate) static HOST_IMDS_URL: Lazy<Url> = Lazy::new(|| HOST_BASE_URL.join("metadata/").unwrap());

/// Trusted Hardware Identity Management (THIM) in IMDS
/// http://169.254.169.254/metadata/THIM
pub(crate) static HOST_THIM_URL: Lazy<Url> = Lazy::new(|| HOST_IMDS_URL.join("THIM/").unwrap());
