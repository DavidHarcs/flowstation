use serde::Deserialize;
use std::fmt;

/// How `issi_whitelist` is interpreted. A bare `Vec` cannot express "deny everyone": an operator
/// who empties the list to lock the cell down actually opens it fully under the legacy semantics.
/// This makes the posture explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WhitelistMode {
    /// No mode configured — legacy semantics: an empty list means "open network", a non-empty
    /// list is an allow-list. Default so existing configs behave exactly as before.
    #[default]
    Auto,
    /// Access control off: every ISSI is allowed whatever the list holds.
    Open,
    /// The list is authoritative. An EMPTY list therefore means DENY-ALL — the only way to
    /// express "lock the cell down", which `Auto` cannot.
    Enforce,
}

impl WhitelistMode {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(WhitelistMode::Auto),
            "open" | "off" | "disabled" => Some(WhitelistMode::Open),
            "enforce" | "strict" => Some(WhitelistMode::Enforce),
            _ => None,
        }
    }
}

/// Air-interface authentication posture (EN 300 392-7 clause 4.1). The base station holds each
/// subscriber's authentication key K and challenges the radio when it registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthenticationMode {
    /// No authentication (the default, and the only option on amateur allocations where the
    /// radios have no K loaded).
    #[default]
    Off,
    /// Radios with a configured K are challenged and must answer correctly; radios without one
    /// register unauthenticated as before. Lets a fleet be keyed up gradually.
    Optional,
    /// Every radio must have a K and must answer correctly, or its registration is rejected.
    Required,
}

impl AuthenticationMode {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "disabled" | "none" => Some(AuthenticationMode::Off),
            "optional" | "known" => Some(AuthenticationMode::Optional),
            "required" | "enforce" | "strict" => Some(AuthenticationMode::Required),
            _ => None,
        }
    }
}

/// Air-interface encryption for a security class 2 cell (EN 300 392-7 clause 6):
/// every radio shares one static cipher key.
///   [security.aie]
///   ksg = "tea3"            # tea1 | tea2 | tea3 — TEA1 is research/interop only (32-bit effective key)
///   sck = "<20 hex digits>" # the 80-bit static cipher key loaded into the radios
///   sckn = 1                # SCK number 1-32, as in the radios
///   sck_vn = 1              # SCK version number
///   encrypt_groups = true   # also encrypt group-addressed signalling and traffic
#[derive(Clone, PartialEq, Eq)]
pub struct CfgAie {
    pub ksg: String,
    pub sck: [u8; 10],
    pub sckn: u8,
    pub sck_vn: u16,
    pub encrypt_groups: bool,
}

impl fmt::Debug for CfgAie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CfgAie {{ ksg: {}, sck: …, sckn: {}, sck_vn: {}, encrypt_groups: {} }}",
            self.ksg, self.sckn, self.sck_vn, self.encrypt_groups
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CfgAieDto {
    pub ksg: Option<String>,
    pub sck: String,
    #[serde(default)]
    pub sckn: Option<u8>,
    #[serde(default)]
    pub sck_vn: Option<u16>,
    #[serde(default)]
    pub encrypt_groups: Option<bool>,
}

pub fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let hex: String = s.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    if hex.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// A subscriber's 128-bit authentication key K (EN 300 392-7 clause 4.1.5), keyed by ISSI.
#[derive(Clone, PartialEq, Eq)]
pub struct SubscriberKey {
    pub issi: u32,
    pub k: [u8; 16],
}

impl fmt::Debug for SubscriberKey {
    /// Never print key material, even in a debug dump of the config.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SubscriberKey {{ issi: {}, k: … }}", self.issi)
    }
}

fn parse_k(s: &str) -> Option<[u8; 16]> {
    parse_hex(s)
}

/// Default cap on the MM client registry. Uplink is unauthenticated (EN 300 392-7 TEA is not
/// implemented), so any radio can claim any of the 2^24 ISSIs — without a cap a registration
/// flood grows the registry until the cell is OOM-killed.
pub const DEFAULT_MAX_REGISTERED_CLIENTS: usize = 2048;
/// Default accepted registrations per minute, per source ISSI. Generous for a real radio (T351
/// plus a post-PTT roaming update), tight enough that one forged ISSI cannot churn the registry.
pub const DEFAULT_REGISTRATION_RATE_LIMIT_PER_MIN: u32 = 30;

/// Access control / security configuration
#[derive(Debug, Clone)]
pub struct CfgSecurity {
    /// ISSI whitelist. Interpretation depends on `whitelist_mode`.
    /// Example config:
    ///   [security]
    ///   issi_whitelist = [2260571, 1001, 1002]
    ///   whitelist_mode = "enforce"   # empty list = deny-all
    pub issi_whitelist: Vec<u32>,
    /// See [`WhitelistMode`].
    pub whitelist_mode: WhitelistMode,
    /// Honour an unauthenticated U-ITSI-DETACH / migrating location update as a teardown of the
    /// claimed ISSI. There is no air-interface authentication, so such a PDU is forgeable and a
    /// replay is a targeted DoS; an operator who does not need detach at all can switch it off.
    pub honour_unauthenticated_detach: bool,
    /// Hard cap on the MM client registry (0 = unlimited, pre-hardening behaviour).
    pub max_registered_clients: usize,
    /// Accepted registrations per minute per source ISSI (0 = disabled).
    pub registration_rate_limit_per_min: u32,
    /// Air-interface authentication posture. Example config:
    ///   [security]
    ///   authentication = "required"
    ///   mutual_authentication = true
    ///   [[security.subscribers]]
    ///   issi = 2260571
    ///   k = "00112233445566778899aabbccddeeff"   # 128-bit K, as loaded into the radio
    pub authentication: AuthenticationMode,
    /// Answer a radio's own challenge (U-AUTHENTICATION DEMAND) and, when we are challenged first,
    /// also challenge back so both sides are authenticated (EN 300 392-7 clause 4.1.4).
    pub mutual_authentication: bool,
    /// Authentication keys by ISSI.
    pub subscribers: Vec<SubscriberKey>,
    /// ISSIs whose `k` could not be parsed (reported at startup, never silently dropped).
    pub invalid_subscriber_keys: Vec<u32>,
    /// Air-interface encryption (class 2). `None` = class 1 cell, everything in clear.
    pub aie: Option<CfgAie>,
    /// Why `[security.aie]` was ignored, if it was present but unusable.
    pub aie_error: Option<String>,
}

impl Default for CfgSecurity {
    fn default() -> Self {
        CfgSecurity {
            issi_whitelist: Vec::new(),
            whitelist_mode: WhitelistMode::Auto,
            honour_unauthenticated_detach: true,
            max_registered_clients: DEFAULT_MAX_REGISTERED_CLIENTS,
            registration_rate_limit_per_min: DEFAULT_REGISTRATION_RATE_LIMIT_PER_MIN,
            authentication: AuthenticationMode::Off,
            mutual_authentication: true,
            subscribers: Vec::new(),
            invalid_subscriber_keys: Vec::new(),
            aie: None,
            aie_error: None,
        }
    }
}

impl CfgSecurity {
    /// Returns true if the given ISSI is allowed to register.
    pub fn is_issi_allowed(&self, issi: u32) -> bool {
        self.allows(issi, None)
    }

    /// Whitelist decision honouring an optional runtime (dashboard) override list, which replaces
    /// the configured list. The mode applies to whichever list is effective, so an operator who
    /// clears the list from the dashboard under `enforce` gets deny-all, not an open cell.
    pub fn allows(&self, issi: u32, override_list: Option<&[u32]>) -> bool {
        let list = override_list.unwrap_or(&self.issi_whitelist);
        match self.whitelist_mode {
            WhitelistMode::Open => true,
            WhitelistMode::Auto => list.is_empty() || list.contains(&issi),
            WhitelistMode::Enforce => list.contains(&issi),
        }
    }

    /// The authentication key K of a subscriber, if one is configured.
    pub fn subscriber_k(&self, issi: u32) -> Option<&[u8; 16]> {
        self.subscribers.iter().find(|s| s.issi == issi).map(|s| &s.k)
    }

    /// One-line description of the air-interface encryption posture, for the startup log.
    pub fn aie_posture(&self) -> String {
        match (&self.aie, &self.aie_error) {
            (Some(a), _) => format!(
                "CLASS 2 — {} with SCK {} (version {}), group traffic {}{}",
                a.ksg.to_uppercase(),
                a.sckn,
                a.sck_vn,
                if a.encrypt_groups { "encrypted" } else { "clear" },
                if a.ksg == "tea1" {
                    " — WARNING: TEA1 keeps only 32 key bits and is NOT secure (research/interop only)"
                } else {
                    ""
                }
            ),
            (None, Some(e)) => format!("CLASS 1 (clear) — [security.aie] IGNORED: {e}"),
            (None, None) => "CLASS 1 — no air-interface encryption".to_string(),
        }
    }

    /// One-line description of the authentication posture, for the startup log.
    pub fn authentication_posture(&self) -> String {
        let n = self.subscribers.len();
        let bad = if self.invalid_subscriber_keys.is_empty() {
            String::new()
        } else {
            format!(
                " — IGNORED {} subscriber(s) with an invalid k: {:?}",
                self.invalid_subscriber_keys.len(),
                self.invalid_subscriber_keys
            )
        };
        match self.authentication {
            AuthenticationMode::Off => format!("OFF — radios are not authenticated ({n} key(s) configured but unused){bad}"),
            AuthenticationMode::Optional => format!("OPTIONAL — {n} keyed ISSI(s) are challenged, others register unauthenticated{bad}"),
            AuthenticationMode::Required => format!("REQUIRED — only the {n} keyed ISSI(s) can register{bad}"),
        }
    }

    /// One-line description of the effective access-control posture, for the startup log. The
    /// whole point is that an operator can read the cell's real posture out of the log rather
    /// than inferring it from an empty TOML array.
    pub fn access_control_posture(&self) -> String {
        let n = self.issi_whitelist.len();
        match self.whitelist_mode {
            WhitelistMode::Open => "OPEN — access control disabled (whitelist_mode = \"open\")".to_string(),
            WhitelistMode::Auto if n == 0 => {
                "OPEN — no issi_whitelist configured; ANY ISSI may register (set whitelist_mode = \"enforce\" to lock down)".to_string()
            }
            WhitelistMode::Auto => format!("ALLOW-LIST — {n} ISSI(s) may register"),
            WhitelistMode::Enforce if n == 0 => "DENY-ALL — whitelist_mode = \"enforce\" with an empty issi_whitelist".to_string(),
            WhitelistMode::Enforce => format!("ALLOW-LIST (enforced) — {n} ISSI(s) may register"),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CfgSecurityDto {
    #[serde(default)]
    pub issi_whitelist: Vec<u32>,
    #[serde(default)]
    pub whitelist_mode: Option<String>,
    #[serde(default)]
    pub honour_unauthenticated_detach: Option<bool>,
    #[serde(default)]
    pub max_registered_clients: Option<usize>,
    #[serde(default)]
    pub registration_rate_limit_per_min: Option<u32>,
    #[serde(default)]
    pub authentication: Option<String>,
    #[serde(default)]
    pub mutual_authentication: Option<bool>,
    #[serde(default)]
    pub subscribers: Vec<SubscriberKeyDto>,
    #[serde(default)]
    pub aie: Option<CfgAieDto>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubscriberKeyDto {
    pub issi: u32,
    pub k: String,
}

pub fn apply_security_patch(dto: CfgSecurityDto) -> CfgSecurity {
    let defaults = CfgSecurity::default();
    let mut subscribers = Vec::new();
    let mut invalid_subscriber_keys = Vec::new();
    for sub in dto.subscribers {
        match parse_k(&sub.k) {
            Some(k) => subscribers.push(SubscriberKey { issi: sub.issi, k }),
            None => invalid_subscriber_keys.push(sub.issi),
        }
    }
    let (aie, aie_error) = match dto.aie {
        None => (None, None),
        Some(a) => {
            let ksg = a.ksg.unwrap_or_else(|| "tea3".to_string()).trim().to_ascii_lowercase();
            let sckn = a.sckn.unwrap_or(1);
            if !matches!(ksg.as_str(), "tea1" | "tea2" | "tea3") {
                (
                    None,
                    Some(format!(
                        "[security.aie] ksg = {ksg:?} is not available (use \"tea1\", \"tea2\" or \"tea3\")"
                    )),
                )
            } else if !(1..=32).contains(&sckn) {
                (None, Some(format!("[security.aie] sckn = {sckn} must be 1-32")))
            } else if let Some(sck) = parse_hex::<10>(&a.sck) {
                (
                    Some(CfgAie {
                        ksg,
                        sck,
                        sckn,
                        sck_vn: a.sck_vn.unwrap_or(1),
                        encrypt_groups: a.encrypt_groups.unwrap_or(true),
                    }),
                    None,
                )
            } else {
                (None, Some("[security.aie] sck must be 20 hex digits (80 bits)".to_string()))
            }
        }
    };
    // An unrecognised mode falls back to "auto"; the effective posture is logged at startup
    // (see access_control_posture) so a typo can't silently pass for a lockdown.
    let whitelist_mode = dto
        .whitelist_mode
        .as_deref()
        .map(|s| WhitelistMode::parse(s).unwrap_or(WhitelistMode::Auto))
        .unwrap_or(WhitelistMode::Auto);
    CfgSecurity {
        issi_whitelist: dto.issi_whitelist,
        whitelist_mode,
        honour_unauthenticated_detach: dto.honour_unauthenticated_detach.unwrap_or(defaults.honour_unauthenticated_detach),
        max_registered_clients: dto.max_registered_clients.unwrap_or(defaults.max_registered_clients),
        registration_rate_limit_per_min: dto
            .registration_rate_limit_per_min
            .unwrap_or(defaults.registration_rate_limit_per_min),
        authentication: dto
            .authentication
            .as_deref()
            .map(|s| AuthenticationMode::parse(s).unwrap_or(AuthenticationMode::Off))
            .unwrap_or(AuthenticationMode::Off),
        mutual_authentication: dto.mutual_authentication.unwrap_or(defaults.mutual_authentication),
        subscribers,
        invalid_subscriber_keys,
        aie,
        aie_error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The footgun: an empty list must stay "open" under the legacy default, but `enforce` must
    /// make the same empty list mean deny-all.
    #[test]
    fn empty_whitelist_semantics_depend_on_mode() {
        let mut cfg = CfgSecurity::default();
        assert!(cfg.is_issi_allowed(1234), "empty list under auto = open network");

        cfg.whitelist_mode = WhitelistMode::Enforce;
        assert!(!cfg.is_issi_allowed(1234), "empty list under enforce = deny-all");

        cfg.issi_whitelist = vec![1234];
        assert!(cfg.is_issi_allowed(1234));
        assert!(!cfg.is_issi_allowed(5678));

        cfg.whitelist_mode = WhitelistMode::Open;
        assert!(cfg.is_issi_allowed(5678), "open ignores the list entirely");
    }

    /// The dashboard override replaces the list but not the mode.
    #[test]
    fn override_list_follows_the_configured_mode() {
        let mut cfg = CfgSecurity { issi_whitelist: vec![1], ..CfgSecurity::default() };
        assert!(cfg.allows(2, Some(&[2])), "override list is authoritative");
        assert!(!cfg.allows(1, Some(&[2])), "config list is ignored when overridden");
        assert!(cfg.allows(9, Some(&[])), "empty override under auto = open");

        cfg.whitelist_mode = WhitelistMode::Enforce;
        assert!(!cfg.allows(9, Some(&[])), "empty override under enforce = deny-all");
    }

    #[test]
    fn subscriber_keys_parse_and_never_debug_print() {
        let dto = CfgSecurityDto {
            authentication: Some("required".into()),
            subscribers: vec![
                SubscriberKeyDto {
                    issi: 1,
                    k: "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff".into(),
                },
                SubscriberKeyDto {
                    issi: 2,
                    k: "too short".into(),
                },
            ],
            ..Default::default()
        };
        let cfg = apply_security_patch(dto);
        assert_eq!(cfg.authentication, AuthenticationMode::Required);
        assert_eq!(cfg.subscriber_k(1).map(|k| k[15]), Some(0xff));
        assert!(cfg.subscriber_k(2).is_none());
        assert_eq!(cfg.invalid_subscriber_keys, vec![2]);
        assert!(!format!("{:?}", cfg.subscribers).contains("ff"));
        assert!(cfg.authentication_posture().contains("IGNORED 1"));
        assert_eq!(CfgSecurity::default().authentication, AuthenticationMode::Off);
    }

    #[test]
    fn aie_section_parses_and_rejects_bad_values() {
        let good = CfgSecurityDto {
            aie: Some(CfgAieDto {
                ksg: Some("TEA3".into()),
                sck: "00:11:22:33:44:55:66:77:88:99".into(),
                sckn: Some(3),
                sck_vn: Some(2),
                encrypt_groups: None,
            }),
            ..Default::default()
        };
        let cfg = apply_security_patch(good);
        let a = cfg.aie.as_ref().expect("aie accepted");
        assert_eq!(
            (a.ksg.as_str(), a.sck[9], a.sckn, a.sck_vn, a.encrypt_groups),
            ("tea3", 0x99, 3, 2, true)
        );
        assert!(!format!("{:?}", cfg.aie).contains("99"), "SCK must not be printed");
        assert!(cfg.aie_posture().starts_with("CLASS 2"));
        let bad = CfgSecurityDto {
            aie: Some(CfgAieDto {
                ksg: Some("tea4".into()),
                sck: "00112233445566778899".into(),
                sckn: None,
                sck_vn: None,
                encrypt_groups: None,
            }),
            ..Default::default()
        };
        let cfg = apply_security_patch(bad);
        assert!(cfg.aie.is_none() && cfg.aie_error.as_deref().unwrap_or("").contains("tea4"));
        let weak = CfgSecurityDto {
            aie: Some(CfgAieDto {
                ksg: Some("tea1".into()),
                sck: "00112233445566778899".into(),
                sckn: None,
                sck_vn: None,
                encrypt_groups: None,
            }),
            ..Default::default()
        };
        assert!(apply_security_patch(weak).aie_posture().contains("NOT secure"));
    }
}
