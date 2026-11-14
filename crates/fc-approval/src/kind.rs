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

/// How a `sign.transaction` authorization presents its token (design 0012,
/// API): a send names the kind it expects, and an `intent-replace` names
/// its intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presented {
    /// `{ token, kind, handle? }`: the kind named.
    Kind(Kind),
    /// `{ token, intent: { id } }`.
    Intent,
    /// Neither: a token that names no kind and no intent signs nothing.
    Unnamed,
}

impl Presented {
    /// Whether a token minted as `kind`, presented this way, is spent by
    /// `sign.transaction`: under a page (`under_page`) a `dapp-send` named
    /// as one; otherwise a `wallet-send` or an `executor-send` named as
    /// itself, or an `intent-replace` with its intent. Anything else is a
    /// `mismatch`, and the token is burnt by its presentation: an
    /// `executor-send` named as a `wallet-send`, a `wallet-send` as an
    /// `executor-send`, a `dapp-send` under `shell`, or a token that names
    /// nothing.
    pub fn spends_transaction(self, kind: Kind, under_page: bool) -> bool {
        match self {
            Presented::Kind(named) if named != kind => false,
            Presented::Kind(Kind::DappSend) => under_page,
            Presented::Kind(Kind::WalletSend | Kind::ExecutorSend) => !under_page,
            Presented::Kind(_) => false,
            Presented::Intent => kind == Kind::IntentReplace && !under_page,
            Presented::Unnamed => false,
        }
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

    /// `sign.transaction` spends a token only as the kind it was minted as,
    /// named, under its own caller: every other pairing of the token's kind,
    /// the named one, and page or not refuses.
    #[test]
    fn a_transaction_spends_only_the_named_kind() {
        let spends = [
            (Presented::Kind(Kind::DappSend), Kind::DappSend, true),
            (Presented::Kind(Kind::WalletSend), Kind::WalletSend, false),
            (
                Presented::Kind(Kind::ExecutorSend),
                Kind::ExecutorSend,
                false,
            ),
            (Presented::Intent, Kind::IntentReplace, false),
        ];
        let named = Kind::ALL
            .into_iter()
            .map(Presented::Kind)
            .chain([Presented::Intent, Presented::Unnamed]);
        for presented in named {
            for kind in Kind::ALL {
                for under_page in [false, true] {
                    assert_eq!(
                        presented.spends_transaction(kind, under_page),
                        spends.contains(&(presented, kind, under_page)),
                        "{presented:?} {kind:?} {under_page}"
                    );
                }
            }
        }
    }
}
