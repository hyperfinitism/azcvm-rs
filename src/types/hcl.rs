// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
use serde::{Deserialize, Serialize};

pub mod report {
	pub const REPORT_PAYLOAD_SIZE: usize = 1184;
    pub const SEV_SNP_REPORT_SIZE: usize = 1184;
    pub const TDX_REPORT_SIZE: usize = 1024;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HclRuntimeClaims {
    // vTPM AK public and EK public in JWKS (JSON Web Key Set) format
    pub keys: Vec<serde_json::Value>,
    // Azure CVM configuration in JSON format
    pub vm_configuration: serde_json::Value,
    // 64-byte data in UPPERCASE HEX format read from vTPM NV index 0x01400002
    pub user_data: String,
}

impl HclRuntimeClaims {
    pub fn from_string(s: &str) -> Result<Self, Error> {
        Ok(serde_json::from_str(s)?)
    }

    pub fn to_string(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(self)?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ReportType {
    SevSnp = 2,
    Tdx = 4,
}

impl TryFrom<u32> for ReportType {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(Self::SevSnp),
            4 => Ok(Self::Tdx),
            v => Err(Error::UnknownReportType(v)),
        }
    }
}

impl From<ReportType> for u32 {
    fn from(value: ReportType) -> Self {
        value as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HashType {
    Sha256 = 1,
    Sha384 = 2,
    Sha512 = 3,
}

impl TryFrom<u32> for HashType {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Sha256),
            2 => Ok(Self::Sha384),
            3 => Ok(Self::Sha512),
            v => Err(Error::UnknownHashType(v)),
        }
    }
}

impl From<HashType> for u32 {
    fn from(value: HashType) -> Self {
        value as u32
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HclReportHeader {
    pub signature: u32,   // vTPM quote signature type (Expected: 0x414c4348 = "HCLA")
    pub version: u32,     // Format version
    pub report_size: u32, // Size of HclAttestationReport
    pub request_type: u32,
    pub status: u32,
    pub reserved: [u8; 12],
}

impl HclReportHeader {
    pub const BYTE_LEN: usize = 32;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::BYTE_LEN {
            return Err(Error::InvalidSize {
                expected: Self::BYTE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            signature: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            version: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            report_size: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            request_type: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            status: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            reserved: bytes[20..32].try_into().unwrap(),
        })
    }

    pub fn as_bytes(&self) -> [u8; Self::BYTE_LEN] {
        let mut out = [0u8; Self::BYTE_LEN];
        out[0..4].copy_from_slice(&self.signature.to_le_bytes());
        out[4..8].copy_from_slice(&self.version.to_le_bytes());
        out[8..12].copy_from_slice(&self.report_size.to_le_bytes());
        out[12..16].copy_from_slice(&self.request_type.to_le_bytes());
        out[16..20].copy_from_slice(&self.status.to_le_bytes());
        out[20..32].copy_from_slice(&self.reserved);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HclRuntimeData {
    pub data_size: u32, // RuntimeData size
    pub version: u32,   // Format version
    pub report_type: ReportType,
    pub hash_type: HashType,
    pub claim_size: u32,        // RuntimeClaims size
    pub runtime_claims: String, // raw UTF-8 string of Runtime Claims JSON - parsed on demand
}

impl HclRuntimeData {
    pub const FIXED_LEN: usize = 20;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(Error::InvalidSize {
                expected: Self::FIXED_LEN,
                actual: bytes.len(),
            });
        }
        let data_size = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let report_raw = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let hash_raw = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let claim_size = u32::from_le_bytes(bytes[16..20].try_into().unwrap());

        let report_type = ReportType::try_from(report_raw)?;
        let hash_type = HashType::try_from(hash_raw)?;

        let search_region = &bytes[Self::FIXED_LEN..];

        let nul_pos = search_region
            .iter()
            .position(|&b| b == 0x00)
            .unwrap_or(search_region.len());

        let claims_bytes = &search_region[..nul_pos];

        let runtime_claims = String::from_utf8(claims_bytes.to_vec())?;

        Ok(Self {
            data_size,
            version,
            report_type,
            hash_type,
            claim_size,
            runtime_claims,
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.data_size as usize);
        v.extend_from_slice(&self.data_size.to_le_bytes());
        v.extend_from_slice(&self.version.to_le_bytes());
        v.extend_from_slice(&u32::from(self.report_type).to_le_bytes());
        v.extend_from_slice(&u32::from(self.hash_type).to_le_bytes());
        v.extend_from_slice(&self.claim_size.to_le_bytes());
        v.extend_from_slice(&self.runtime_claims.clone().into_bytes());
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HclAttestationReport {
    pub header: HclReportHeader,
    pub report_payload: Vec<u8>,
    pub runtime_data: HclRuntimeData,
}

impl HclAttestationReport {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let header = HclReportHeader::from_bytes(&bytes[0..HclReportHeader::BYTE_LEN])?;
        let payload_end = HclReportHeader::BYTE_LEN + report::REPORT_PAYLOAD_SIZE;
        if bytes.len() < payload_end {
            return Err(Error::InvalidSize {
                expected: payload_end,
                actual: bytes.len(),
            });
        }
        let report_payload = bytes[HclReportHeader::BYTE_LEN..payload_end].to_vec();
        let runtime_data = HclRuntimeData::from_bytes(&bytes[payload_end..])?;
        Ok(Self {
            header,
            report_payload,
            runtime_data,
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.header.as_bytes());
        v.extend_from_slice(&self.report_payload);
        v.extend_from_slice(&self.runtime_data.as_bytes());
        v
    }
}
