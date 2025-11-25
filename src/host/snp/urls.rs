// SPDX-License-Identifier: Apache-2.0

use crate::host::urls::HOST_THIM_URL;

use once_cell::sync::Lazy;
use url::Url;

/// Host-cached VCEK Certificate Chain
/// http://169.254.169.254/metadata/THIM/amd/certification
pub(crate) static HOST_AMD_CERTS_URL: Lazy<Url> =
    Lazy::new(|| HOST_THIM_URL.join("amd/certification").unwrap());
