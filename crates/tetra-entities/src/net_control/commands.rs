// ---------------------------------------------------------------------------
// Command / CommandResponse — concrete enums sent through the channel
//
// The command server sends a Command; the stack processes it and returns
// a CommandResponse.  Placeholder variants are provided for now.
// ---------------------------------------------------------------------------

use bitcode::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Command received from the remote command server.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub enum ControlCommand {
    /// Send an SDS for local delivery
    SendSds {
        handle: u32,
        source_ssi: u32,
        dest_ssi: u32,
        dest_is_group: bool,
        len_bits: u16,
        payload: Vec<u8>,
    },

    /// Send an already-built SDS Type-4 payload for local delivery.
    SendRawSdsType4 {
        handle: u32,
        source_ssi: u32,
        dest_ssi: u32,
        dest_is_group: bool,
        len_bits: u16,
        payload: Vec<u8>,
    },

    /// Forcibly deregister a terminal from the BS
    KickMs { issi: u32 },

    /// Send the cell's static cipher key to one radio over the air (D-OTAR SCK PROVIDE,
    /// EN 300 392-7 clause 4.5.2.2). The radio must hold the authentication key K listed
    /// for it under [[security.subscribers]]. Local-only.
    OtarSck { issi: u32 },

    /// Transmit a D-OTAR SCK PROVIDE built from key material already sealed by an
    /// external Key Management Facility (KMF, "Model B"). FlowStation holds no
    /// authentication key K in this mode — it only transmits the pre-sealed PDU.
    /// `sckn_air` and `ksg_air` are the 0-based on-air values; `ssck` is the
    /// sealed SCK (SEALED_LEN bytes) and `rso` the seed (RSO_LEN bytes).
    OtarSckSealed {
        issi: u32,
        sckn_air: u8,
        sck_vn: u16,
        ksg_air: u8,
        ssck: Vec<u8>,
        rso: Vec<u8>,
    },

    /// As `OtarSckSealed`, but for a Group Cipher Key (D-OTAR GCK PROVIDE). The
    /// KMF seals the GCK under the GSKO (TA81); FlowStation only transmits.
    /// `gckn` is the 16-bit GCK number; the GCK is associated to group `gssi`.
    OtarGckSealed {
        issi: u32,
        gckn: u16,
        gck_vn: u16,
        ksg_air: u8,
        gssi: u32,
        sgck: Vec<u8>,
        rso: Vec<u8>,
    },

    /// Dynamic Group Number Assignment (SS-DGNA, ETSI EN 300 392-2 §16).
    ///
    /// BS-initiated: attach (or detach) a single GSSI on an already-registered
    /// terminal over the air, by sending it an unsolicited D-ATTACH/DETACH GROUP
    /// IDENTITY. Local-only — no Brew propagation is performed for this command.
    Dgna {
        /// Target terminal (must be registered on the cell).
        issi: u32,
        /// Group to assign/remove.
        gssi: u32,
        /// Optional TG alias sent in the SS-DGNA mnemonic group name.
        mnemonic: Option<String>,
        /// SS-DGNA attachment mode (Table 51). Used for assign only; deassign ignores it.
        attachment_mode: u8,
        /// `true` = assign/attach the group, `false` = deassign/detach it.
        attach: bool,
    },

    /// Restart the FlowStation service (systemctl restart tetra)
    RestartService,

    /// Stop the FlowStation service (systemctl stop tetra)
    ShutdownService,

    /// Add a live SDS message to the broadcast queue.
    /// The message will be transmitted to all MSs on the cell at the next HMD interval,
    /// round-robining with the static Home Mode Display text.
    /// `repeat_count = 0` means repeat indefinitely; `> 0` auto-removes after N transmissions.
    AddLiveSds {
        text: String,
        protocol_id: u8,
        source_issi: u32,
        repeat_count: u32,
    },

    /// Remove a live SDS message from the queue by its ID.
    DeleteLiveSds { id: u32 },

    /// Remove all live SDS messages from the queue.
    ClearLiveSds,

    /// Operator-clear an active emergency for one ISSI (`issi == 0` clears all). Local-only;
    /// clears the source session so a subsequent emergency re-send raises a fresh alarm.
    ClearEmergency { issi: u32 },

    /// Ambience listening (SS-AL). Set up a receive-only speech call to `issi` in which the
    /// target radio answers and keys on its own (indicated on the radio — not covert);
    /// `enable == false` releases it. Wire-compatible with brew-server's
    /// `AmbienceListen { issi, enable }`, which fires it at the base station hosting the ISSI.
    AmbienceListen { issi: u32, enable: bool },

    /// Placeholder command A.
    CommandA { handle: u32, parameter: u32 },
    /// Placeholder command B.
    TestCmdB {
        handle: u32,
        source_ssi: u32,
        is_group: bool,
        payload: Vec<u8>,
    },
}

/// Response sent back after processing a [`ControlCommand`].
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub enum ControlResponse {
    CommandAResponse { handle: u32, result: u32 },
    SendSdsResponse { handle: u32, success: bool },
    KickMsResponse { issi: u32, success: bool },
    AmbienceListenResponse { issi: u32, success: bool },
}
