//! D-OTAR GCK PROVIDE (EN 300 392-7 clause 4.5.3, Table A.12). Delivers one or
//! more Group Cipher Keys to a radio, each sealed with TA81 under the GSKO.
//! Built for KMF-driven OTAR (the KMF seals; the SwMI only transmits).
//!
//! Mirrors `otar_sck`'s D-OTAR SCK PROVIDE, reusing its shared header/tail and
//! session-key helpers; only the per-key element (GCK key and identifier) and
//! the trailing group-association differ.

use tetra_core::typed_pdu_fields::*;
use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

use super::otar_sck::{
    expect_sub_type, read_bytes, read_header, read_tail, write_bytes, write_tail, OtarSessionKey,
    RSO_LEN, SEALED_LEN,
};
use crate::mm::enums::mm_pdu_type_dl::MmPduTypeDl;
use crate::mm::enums::mm_pdu_type_ul::MmPduTypeUl;
use crate::mm::enums::otar_sub_type::{OtarSubType, ProvisionResult};

/// GCK key and identifier (Table A.62): GCKN (16) ‖ GCK-VN (16) ‖ sealed GCK (120).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GckKeyAndIdentifier {
    pub gckn: u16,
    pub gck_vn: u16,
    pub sgck: [u8; SEALED_LEN],
}

impl GckKeyAndIdentifier {
    fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let gckn = buffer.read_field(16, "gckn")? as u16;
        let gck_vn = buffer.read_field(16, "gck_vn")? as u16;
        let sgck = read_bytes::<SEALED_LEN>(buffer, "sgck")?;
        Ok(GckKeyAndIdentifier { gckn, gck_vn, sgck })
    }

    fn to_bitbuf(&self, buffer: &mut BitBuffer) {
        buffer.write_bits(u64::from(self.gckn), 16);
        buffer.write_bits(u64::from(self.gck_vn), 16);
        write_bytes(buffer, &self.sgck);
    }
}

/// Group association (Table A.12 / A.8.31): the provided GCK is associated
/// either by its own GCKN (bit 0) or to a specific group GSSI (bit 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupAssociation {
    Gckn,
    Gssi(u32),
}

/// D-OTAR GCK PROVIDE PDU.
#[derive(Debug, PartialEq, Eq)]
pub struct DOtarGckProvide {
    pub ack_required: bool,
    pub explicit_response: bool,
    pub max_response_timer: u16,
    pub session_key: OtarSessionKey,
    /// 0 … 7 keys.
    pub keys: Vec<GckKeyAndIdentifier>,
    /// KSG number (A.8.41): 0 = TEA1 … 3 = TEA4.
    pub ksg_number: u8,
    pub group_association: GroupAssociation,
    pub otar_retry_interval: u8,
    pub address_extension: Option<u64>,
    pub proprietary: Option<Type3FieldGeneric>,
}

impl DOtarGckProvide {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        expect_sub_type(read_header(buffer, true)?, OtarSubType::GckDemandProvide)?;
        let ack_required = buffer.read_field(1, "acknowledgement_flag")? == 1;
        let flag = buffer.read_field(1, "explicit_response")? == 1;
        let explicit_response = ack_required && flag;
        let max_response_timer = buffer.read_field(16, "max_response_timer")? as u16;
        let group = buffer.read_field(1, "session_key")? == 1;
        let session_key = if group {
            OtarSessionKey::Group { gsko_vn: buffer.read_field(16, "gsko_vn")? as u16 }
        } else {
            OtarSessionKey::Individual { rso: read_bytes::<RSO_LEN>(buffer, "rso")? }
        };
        let n = buffer.read_field(3, "number_of_gcks_provided")?;
        let mut keys = Vec::with_capacity(n as usize);
        for _ in 0..n {
            keys.push(GckKeyAndIdentifier::from_bitbuf(buffer)?);
        }
        let ksg_number = buffer.read_field(4, "ksg_number")? as u8;
        let group_association = if buffer.read_field(1, "group_association")? == 1 {
            GroupAssociation::Gssi(buffer.read_field(24, "gssi")? as u32)
        } else {
            GroupAssociation::Gckn
        };
        let otar_retry_interval = buffer.read_field(3, "otar_retry_interval")? as u8;
        let (address_extension, proprietary) = read_tail(buffer, false)?;
        Ok(DOtarGckProvide {
            ack_required,
            explicit_response,
            max_response_timer,
            session_key,
            keys,
            ksg_number,
            group_association,
            otar_retry_interval,
            address_extension,
            proprietary,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if self.keys.len() > 7 {
            return Err(PduParseErr::InvalidValue {
                field: "number_of_gcks_provided",
                value: self.keys.len() as u64,
            });
        }
        buffer.write_bits(MmPduTypeDl::DOtar.into_raw(), 4);
        buffer.write_bits(OtarSubType::GckDemandProvide.into_raw(), 4);
        buffer.write_bits(self.ack_required as u64, 1);
        buffer.write_bits((self.ack_required && self.explicit_response) as u64, 1);
        buffer.write_bits(u64::from(self.max_response_timer), 16);
        match &self.session_key {
            OtarSessionKey::Individual { rso } => {
                buffer.write_bits(0, 1);
                write_bytes(buffer, rso);
            }
            OtarSessionKey::Group { gsko_vn } => {
                buffer.write_bits(1, 1);
                buffer.write_bits(u64::from(*gsko_vn), 16);
            }
        }
        buffer.write_bits(self.keys.len() as u64, 3);
        for k in &self.keys {
            k.to_bitbuf(buffer);
        }
        buffer.write_bits(u64::from(self.ksg_number & 0xF), 4);
        match &self.group_association {
            GroupAssociation::Gckn => {
                buffer.write_bits(0, 1);
            }
            GroupAssociation::Gssi(gssi) => {
                buffer.write_bits(1, 1);
                buffer.write_bits(u64::from(*gssi & 0x00FF_FFFF), 24);
            }
        }
        buffer.write_bits(u64::from(self.otar_retry_interval & 0x7), 3);
        write_tail(buffer, self.address_extension);
        Ok(())
    }
}

/// One "GCK number and result" element (A.8.28a): GCKN, GCK-VN and the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GckNumberAndResult {
    pub gckn: u16,
    pub gck_vn: u16,
    pub result: ProvisionResult,
    /// Present when the result is "incorrect key version number".
    pub current_gck_vn: Option<u16>,
}

/// U-OTAR GCK RESULT (Table A.14): the MS accepts or rejects each provided GCK.
#[derive(Debug, PartialEq, Eq)]
pub struct UOtarGckResult {
    pub results: Vec<GckNumberAndResult>,
    pub address_extension: Option<u64>,
    pub proprietary: Option<Type3FieldGeneric>,
}

impl UOtarGckResult {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        expect_sub_type(read_header(buffer, false)?, OtarSubType::GckResultReject)?;
        let n = buffer.read_field(3, "number_of_gcks_provided")?;
        let mut results = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let gckn = buffer.read_field(16, "gckn")? as u16;
            let gck_vn = buffer.read_field(16, "gck_vn")? as u16;
            let result = ProvisionResult::from_raw(buffer.read_field(3, "provision_result")?);
            let current_gck_vn = if result == ProvisionResult::IncorrectKeyVersion {
                Some(buffer.read_field(16, "current_gck_vn")? as u16)
            } else {
                None
            };
            results.push(GckNumberAndResult { gckn, gck_vn, result, current_gck_vn });
        }
        let (address_extension, proprietary) = read_tail(buffer, true)?;
        Ok(UOtarGckResult { results, address_extension, proprietary })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(MmPduTypeUl::UOtar.into_raw(), 4);
        buffer.write_bits(OtarSubType::GckResultReject.into_raw(), 4);
        buffer.write_bits(self.results.len() as u64, 3);
        for r in &self.results {
            buffer.write_bits(u64::from(r.gckn), 16);
            buffer.write_bits(u64::from(r.gck_vn), 16);
            buffer.write_bits(r.result.into_raw(), 3);
            if r.result == ProvisionResult::IncorrectKeyVersion {
                buffer.write_bits(u64::from(r.current_gck_vn.unwrap_or(0)), 16);
            }
        }
        write_tail(buffer, self.address_extension);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gck_result_round_trips() {
        let pdu = UOtarGckResult {
            results: vec![
                GckNumberAndResult { gckn: 0x1234, gck_vn: 7, result: ProvisionResult::Accepted, current_gck_vn: None },
                GckNumberAndResult {
                    gckn: 0x00AB,
                    gck_vn: 2,
                    result: ProvisionResult::IncorrectKeyVersion,
                    current_gck_vn: Some(5),
                },
            ],
            address_extension: None,
            proprietary: None,
        };
        let mut buf = BitBuffer::new_autoexpand(128);
        pdu.to_bitbuf(&mut buf).expect("encode");
        buf.seek(0);
        let decoded = UOtarGckResult::from_bitbuf(&mut buf).expect("decode");
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn gck_provide_round_trips() {
        let pdu = DOtarGckProvide {
            ack_required: true,
            explicit_response: true,
            max_response_timer: 0,
            session_key: OtarSessionKey::Individual { rso: [0xA5; RSO_LEN] },
            keys: vec![GckKeyAndIdentifier { gckn: 0x1234, gck_vn: 7, sgck: [0x3C; SEALED_LEN] }],
            ksg_number: 1,
            group_association: GroupAssociation::Gssi(314946),
            otar_retry_interval: 0,
            address_extension: None,
            proprietary: None,
        };
        let mut buf = BitBuffer::new_autoexpand(256);
        pdu.to_bitbuf(&mut buf).expect("encode");
        buf.seek(0);
        let decoded = DOtarGckProvide::from_bitbuf(&mut buf).expect("decode");
        assert_eq!(decoded, pdu);
    }
}
