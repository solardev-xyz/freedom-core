//! The eleven token kinds (design 0012, "Tokens").

/// What a confirmation is for. The names are the reference's
/// (`signing-confirmation.js`, `KINDS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    WalletSend,
    DappSend,
    SignMessage,
    SignTypedData,
    SafeSend,
    SafeMessage,
    IntentResend,
    IntentReplace,
    IntentClose,
    ExecutorSend,
    X402Payment,
}

/// Whether a kind's token is for a page: minted with the request's
/// `PageContext` and 0011's handle, and spent only for that page and
/// handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageRule {
    /// A page kind: `dapp-send`, `sign-message`, `sign-typed-data` and
    /// `safe-message`.
    Required,
    /// `safe-send`: a site's names its page, a wallet's none. They are two
    /// kinds to the core, and neither is spent as the other.
    Optional,
    /// A wallet kind.
    Forbidden,
}

/// Whether a token is a page's or the wallet's: a `safe-send`'s comes from
/// whether it names a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Page,
    Wallet,
}

impl Kind {
    pub const ALL: [Kind; 11] = [
        Kind::WalletSend,
        Kind::DappSend,
        Kind::SignMessage,
        Kind::SignTypedData,
        Kind::SafeSend,
        Kind::SafeMessage,
        Kind::IntentResend,
        Kind::IntentReplace,
        Kind::IntentClose,
        Kind::ExecutorSend,
        Kind::X402Payment,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Kind::WalletSend => "wallet-send",
            Kind::DappSend => "dapp-send",
            Kind::SignMessage => "sign-message",
            Kind::SignTypedData => "sign-typed-data",
            Kind::SafeSend => "safe-send",
            Kind::SafeMessage => "safe-message",
            Kind::IntentResend => "intent-resend",
            Kind::IntentReplace => "intent-replace",
            Kind::IntentClose => "intent-close",
            Kind::ExecutorSend => "executor-send",
            Kind::X402Payment => "x402-payment",
        }
    }

    pub fn from_name(name: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.name() == name)
    }

    pub fn page_rule(self) -> PageRule {
        match self {
            Kind::DappSend | Kind::SignMessage | Kind::SignTypedData | Kind::SafeMessage => {
                PageRule::Required
            }
            Kind::SafeSend => PageRule::Optional,
            Kind::WalletSend
            | Kind::IntentResend
            | Kind::IntentReplace
            | Kind::IntentClose
            | Kind::ExecutorSend
            | Kind::X402Payment => PageRule::Forbidden,
        }
    }

    /// Whether the kind binds an account (a wallet's index, or a Safe's).
    /// The intent kinds bind the sender instead, from main's record.
    pub fn takes_account(self) -> bool {
        !matches!(
            self,
            Kind::IntentResend | Kind::IntentReplace | Kind::IntentClose
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for kind in Kind::ALL {
            assert_eq!(Kind::from_name(kind.name()), Some(kind));
        }
        // The reference's twelfth kind, #1023's cap edit, isn't one of
        // 0012's eleven; nor is any other text.
        for other in ["x402-cap-update", "", "Wallet-Send", "wallet_send"] {
            assert_eq!(Kind::from_name(other), None, "{other}");
        }
    }
}
