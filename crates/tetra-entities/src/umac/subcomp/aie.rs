//! Air-interface encryption for a security class 2 cell (ETSI EN 300 392-7
//! clause 6), as the MAC applies it: one static cipher key bound to this cell
//! (ECK = TB5(SCK, carrier, location area, colour code)), a key stream per MAC
//! PDU from the burst's slot numbering, and encrypted short identities in place
//! of SSIs on every encrypted PDU.

use std::sync::Arc;

use tetra_config::bluestation::config::StackConfig;
use tetra_core::{BitBuffer, PhyBlockNum, SsiType, TdmaTime, TetraAddress};
use tetra_security::aie::{Class2Keys, KssOffset, key_stream};
use tetra_security::keys::CipherKey;
use tetra_security::ksg::{Iv, KsgId};

/// The cell's live encryption state. Shared read-only between the UMAC and
/// its schedulers.
pub struct AieCell {
    keys: Class2Keys,
    eck: CipherKey,
    pub encrypt_groups: bool,
}

impl std::fmt::Debug for AieCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AieCell {{ ksg: {:?}, sckn: {}, sck_vn: {}, encrypt_groups: {} }}", self.keys.ksg, self.keys.sckn, self.keys.sck_vn, self.encrypt_groups)
    }
}

impl AieCell {
    /// Build from the configuration, or `None` for a class 1 (clear) cell.
    pub fn from_config(cfg: &StackConfig) -> Option<Arc<AieCell>> {
        let aie = cfg.security.active_aie()?;
        let ksg = match aie.ksg.as_str() {
            "tea1" => KsgId::Tea1,
            "tea2" => KsgId::Tea2,
            _ => KsgId::Tea3,
        };
        let keys = Class2Keys { ksg, sck: CipherKey(aie.sck), sckn: aie.sckn, sck_vn: aie.sck_vn };
        // TB5 binds the key to this cell: carrier number (12 bits), location area, colour code.
        let eck = keys.eck(cfg.cell.main_carrier & 0x0FFF, cfg.cell.location_area, cfg.cell.colour_code);
        Some(Arc::new(AieCell { keys, eck, encrypt_groups: aie.encrypt_groups }))
    }

    /// SCK number for the SYSINFO security information element.
    pub fn sckn(&self) -> u8 {
        self.keys.sckn
    }

    /// Value of the encryption mode element on an encrypted downlink MAC header.
    pub fn encryption_mode(&self) -> u8 {
        self.keys.encryption_mode()
    }

    /// The encrypted short identity used on air in place of an SSI.
    pub fn esi(&self, addr: TetraAddress) -> TetraAddress {
        TetraAddress::new(self.keys.esi(addr.ssi), SsiType::Esi)
    }

    /// The identity behind an ESI a radio addressed us with. The radio tells us
    /// nothing about the address type, so the caller decides (individual for an
    /// uplink PDU's own source address).
    pub fn resolve_esi(&self, esi: u32, ssi_type: SsiType) -> TetraAddress {
        TetraAddress::new(self.keys.ssi_from_esi(esi), ssi_type)
    }

    /// The initial value of a burst (clause 6.3.2.1): its slot numbering and direction.
    pub fn iv(ts: TdmaTime, uplink: bool) -> Iv {
        Iv::from_frame(ts.t, ts.f, ts.m, ts.h, uplink)
    }

    /// XOR the next `num_bits` of `buf` (from its current position) with the key
    /// stream for this burst, leaving the position where it was. `block` selects
    /// the key stream offset: the second half slot starts at KSS(216).
    /// Encryption and decryption are the same operation.
    pub fn apply(&self, buf: &mut BitBuffer, num_bits: usize, ts: TdmaTime, uplink: bool, block: PhyBlockNum) {
        if num_bits == 0 {
            return;
        }
        let offset = if block == PhyBlockNum::Block2 { KssOffset::Second } else { KssOffset::First };
        let Some(kss) = key_stream(self.keys.ksg, &self.eck, AieCell::iv(ts, uplink), offset, num_bits) else {
            return;
        };
        // Pack the bit-per-byte key stream into bytes for the buffer's XOR.
        let mut packed = vec![0u8; num_bits.div_ceil(8)];
        for (i, bit) in kss.iter().enumerate() {
            packed[i / 8] |= bit << (7 - (i % 8));
        }
        let pos = buf.get_pos();
        buf.xor_bytearr(&packed, num_bits);
        buf.seek_rel(pos as isize - buf.get_pos() as isize);
    }
}

impl AieCell {
    /// XOR a bit array (one bit per byte, as the LMAC hands speech frames up) with the key
    /// stream for this burst.
    pub fn apply_bitarr(&self, bits: &mut [u8], ts: TdmaTime, uplink: bool, block: PhyBlockNum) {
        let offset = if block == PhyBlockNum::Block2 { KssOffset::Second } else { KssOffset::First };
        if let Some(kss) = key_stream(self.keys.ksg, &self.eck, AieCell::iv(ts, uplink), offset, bits.len()) {
            for (b, k) in bits.iter_mut().zip(kss) {
                *b ^= k;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tetra_security::keys::CipherKey;

    fn cell() -> AieCell {
        let keys = Class2Keys { ksg: KsgId::Tea3, sck: "00112233445566778899".parse::<CipherKey>().unwrap(), sckn: 2, sck_vn: 5 };
        let eck = keys.eck(1521, 2, 1);
        AieCell { keys, eck, encrypt_groups: true }
    }

    #[test]
    fn apply_round_trips_in_place_and_keeps_position() {
        let c = cell();
        let ts = TdmaTime { t: 2, f: 7, m: 11, h: 3 };
        let mut buf = BitBuffer::from_bitstr("1011001110001111000011111000001111100000111110000011111000001111");
        buf.seek(8); // pretend the first byte is a MAC header
        let before = buf.to_bitstr();
        c.apply(&mut buf, 56, ts, false, PhyBlockNum::Both);
        assert_eq!(buf.get_pos(), 8);
        let encrypted = buf.to_bitstr();
        assert_eq!(&encrypted[..8], &before[..8], "header untouched");
        assert_ne!(encrypted, before);
        c.apply(&mut buf, 56, ts, false, PhyBlockNum::Both);
        assert_eq!(buf.to_bitstr(), before);
        // A different slot, direction or half gives a different stream.
        let mut a = BitBuffer::from_bitstr("0000000000000000");
        let mut b = BitBuffer::from_bitstr("0000000000000000");
        let mut d = BitBuffer::from_bitstr("0000000000000000");
        c.apply(&mut a, 16, ts, false, PhyBlockNum::Block1);
        c.apply(&mut b, 16, ts, true, PhyBlockNum::Block1);
        c.apply(&mut d, 16, ts, false, PhyBlockNum::Block2);
        assert_ne!(a.to_bitstr(), b.to_bitstr());
        assert_ne!(a.to_bitstr(), d.to_bitstr());
    }

    #[test]
    fn esi_is_reversible() {
        let c = cell();
        let addr = TetraAddress::new(2358245, SsiType::Issi);
        let esi = c.esi(addr);
        assert_eq!(esi.ssi_type, SsiType::Esi);
        assert_ne!(esi.ssi, addr.ssi);
        assert_eq!(c.resolve_esi(esi.ssi, SsiType::Issi), addr);
        assert_eq!(c.encryption_mode(), 0b11);
    }
}
