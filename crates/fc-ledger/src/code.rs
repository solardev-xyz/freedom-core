//! The `LEDGER_*` codes an operation ends with (design 0016, API, "Errors"):
//! today's twelve (`errors.js`), and the four new ones. Main shows
//! `errors.js`'s text for a code; the core names only the code.

/// A device's failure, `device_failed`'s `data.ledger`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LedgerCode {
    DeviceNotFound,
    DeviceLocked,
    EthAppNotOpen,
    UserRejected,
    Disconnected,
    Busy,
    WrongDevice,
    BlindSigningRequired,
    BadSignature,
    AddressMismatch,
    AccountUnchecked,
    Unknown,
    /// No answer to an APDU the user doesn't confirm in 15 s (new).
    Unresponsive,
    /// No answer to one the user confirms in 5 minutes (new).
    Timeout,
    /// Typed data, a message or a transaction a Ledger can't carry (new,
    /// deviation `device-bounds`).
    TooLarge,
    /// An empty `personal_sign` (new, deviation `empty-message`).
    EmptyMessage,
}

impl LedgerCode {
    pub fn as_str(self) -> &'static str {
        match self {
            LedgerCode::DeviceNotFound => "LEDGER_DEVICE_NOT_FOUND",
            LedgerCode::DeviceLocked => "LEDGER_DEVICE_LOCKED",
            LedgerCode::EthAppNotOpen => "LEDGER_ETH_APP_NOT_OPEN",
            LedgerCode::UserRejected => "LEDGER_USER_REJECTED",
            LedgerCode::Disconnected => "LEDGER_DISCONNECTED",
            LedgerCode::Busy => "LEDGER_BUSY",
            LedgerCode::WrongDevice => "LEDGER_WRONG_DEVICE",
            LedgerCode::BlindSigningRequired => "LEDGER_BLIND_SIGNING_REQUIRED",
            LedgerCode::BadSignature => "LEDGER_BAD_SIGNATURE",
            LedgerCode::AddressMismatch => "LEDGER_ADDRESS_MISMATCH",
            LedgerCode::AccountUnchecked => "LEDGER_ACCOUNT_UNCHECKED",
            LedgerCode::Unknown => "LEDGER_UNKNOWN",
            LedgerCode::Unresponsive => "LEDGER_UNRESPONSIVE",
            LedgerCode::Timeout => "LEDGER_TIMEOUT",
            LedgerCode::TooLarge => "LEDGER_TOO_LARGE",
            LedgerCode::EmptyMessage => "LEDGER_EMPTY_MESSAGE",
        }
    }

    /// A status word other than `9000`, as `errors.js`'s `STATUS_TO_CODE`
    /// maps it; any other status is `LEDGER_UNKNOWN`.
    pub fn for_status(status: u16) -> LedgerCode {
        match status {
            0x5515 | 0x6982 => LedgerCode::DeviceLocked,
            0x6985 | 0x5501 => LedgerCode::UserRejected,
            0x6a80 => LedgerCode::BlindSigningRequired,
            0x6511 | 0x6d00 | 0x6e00 | 0x6e01 => LedgerCode::EthAppNotOpen,
            _ => LedgerCode::Unknown,
        }
    }
}

/// `shell.ledger_apdu`'s `{ failed }`: main couldn't exchange the APDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Failed {
    /// No device to open.
    NotFound,
    /// The device is held elsewhere.
    Busy,
    /// A write or read failed: the device was unplugged.
    Disconnected,
    /// No answer in 15 s to an APDU the user doesn't confirm.
    Unresponsive,
    /// No answer in 5 minutes to one the user confirms.
    Timeout,
}

impl Failed {
    /// The wire's name: `not_found`, `busy`, `disconnected`,
    /// `unresponsive` or `timeout`.
    pub fn parse(text: &str) -> Option<Failed> {
        match text {
            "not_found" => Some(Failed::NotFound),
            "busy" => Some(Failed::Busy),
            "disconnected" => Some(Failed::Disconnected),
            "unresponsive" => Some(Failed::Unresponsive),
            "timeout" => Some(Failed::Timeout),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Failed::NotFound => "not_found",
            Failed::Busy => "busy",
            Failed::Disconnected => "disconnected",
            Failed::Unresponsive => "unresponsive",
            Failed::Timeout => "timeout",
        }
    }

    /// The code the operation ends with.
    pub fn code(self) -> LedgerCode {
        match self {
            Failed::NotFound => LedgerCode::DeviceNotFound,
            Failed::Busy => LedgerCode::Busy,
            Failed::Disconnected => LedgerCode::Disconnected,
            Failed::Unresponsive => LedgerCode::Unresponsive,
            Failed::Timeout => LedgerCode::Timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_table() {
        for (status, code) in [
            (0x5515, "LEDGER_DEVICE_LOCKED"),
            (0x6982, "LEDGER_DEVICE_LOCKED"),
            (0x6985, "LEDGER_USER_REJECTED"),
            (0x5501, "LEDGER_USER_REJECTED"),
            (0x6a80, "LEDGER_BLIND_SIGNING_REQUIRED"),
            (0x6511, "LEDGER_ETH_APP_NOT_OPEN"),
            (0x6d00, "LEDGER_ETH_APP_NOT_OPEN"),
            (0x6e00, "LEDGER_ETH_APP_NOT_OPEN"),
            (0x6e01, "LEDGER_ETH_APP_NOT_OPEN"),
            (0x6f00, "LEDGER_UNKNOWN"),
            (0x6a81, "LEDGER_UNKNOWN"),
            (0x0000, "LEDGER_UNKNOWN"),
            (0xffff, "LEDGER_UNKNOWN"),
        ] {
            assert_eq!(
                LedgerCode::for_status(status).as_str(),
                code,
                "{status:04x}"
            );
        }
    }

    #[test]
    fn mains_failures() {
        for (text, code) in [
            ("not_found", "LEDGER_DEVICE_NOT_FOUND"),
            ("busy", "LEDGER_BUSY"),
            ("disconnected", "LEDGER_DISCONNECTED"),
            ("unresponsive", "LEDGER_UNRESPONSIVE"),
            ("timeout", "LEDGER_TIMEOUT"),
        ] {
            let failed = Failed::parse(text).unwrap();
            assert_eq!(failed.as_str(), text);
            assert_eq!(failed.code().as_str(), code);
        }
        assert_eq!(Failed::parse("NotFound"), None);
    }
}
