#![forbid(unsafe_code)]

//! Identify by contract: the Party the contract the first section is bound to
//! names as its sender.
//!
//! A contract is agreed with somebody. When a Message's first section has
//! been bound to `partner-x-orders-v2`, the binding itself says who is on the
//! other side of it, and this identifier reads that: the contract-to-Party
//! mapping is configured into it, and the Party the bound contract maps to is
//! the claim. It is *detected* — read out of what is there — and it proves
//! nothing: a contract binding is a statement about the content's shape, and
//! anyone who can produce the shape can produce the binding. Whether a Party
//! recognised only this way may send this contract is authorization's
//! question (ADR-0050 section 5, `authorize/contract`).
//!
//! A section bound to no contract, or to one the mapping does not name,
//! carries nothing this identifier recognises. The evidence names the
//! contract, so the record says which binding the claim came from:
//!
//! ```text
//! contract.name   the contract the first section is bound to   evidence
//! ```
//!
//! The interchange senders ADR-0050 lists beside this leaf — ISA06, UNB S002,
//! MSH-3 — are promoted by the EDI and HL7 content technologies and read by
//! `identify/message` under their promoted names; this leaf reads the
//! binding, not the envelope.

use identify::{IdentifyError, MessageIdentifier, Presented};
use message::Message;
use xcore::Mechanism;

/// The evidence name carrying the contract the claim was read from.
pub const CONTRACT: &str = "contract.name";

/// Reads the Party the bound contract names, from a configured mapping.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Contract {
    parties: Vec<(String, String)>,
}

impl Contract {
    /// A mapping of contract name to the Party it is agreed with.
    #[must_use]
    pub fn new(parties: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>) -> Self {
        Self {
            parties: parties
                .into_iter()
                .map(|(contract, party)| (contract.into(), party.into()))
                .collect(),
        }
    }

    /// The Party `contract` is agreed with, where the mapping names one.
    #[must_use]
    pub fn party(&self, contract: &str) -> Option<&str> {
        self.parties
            .iter()
            .find(|(candidate, _)| candidate == contract)
            .map(|(_, party)| party.as_str())
    }
}

impl MessageIdentifier for Contract {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::contract()
    }

    fn identify(&self, message: &Message) -> Result<Option<Presented>, IdentifyError> {
        let Some(contract) = message
            .sections()
            .first()
            .and_then(|section| section.contract.as_deref())
        else {
            return Ok(None);
        };
        if contract.trim().is_empty() {
            return Err(IdentifyError::new(
                "the first section is bound to a contract with no name",
            ));
        }

        Ok(self.party(contract).map(|party| {
            Presented::detected(self.mechanism(), party).with_evidence(CONTRACT, contract)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::MessageContext;
    use message::{MessageSection, MessageTreatment};
    use stream::Stream;
    use xcore::{Established, Layer, MessageId, SectionId, StreamId};

    fn message(contract: Option<&str>) -> Message {
        Message::received(
            MessageId::new(1),
            vec![MessageSection {
                section_id: SectionId::new(2),
                name: None,
                stream: Stream::new(StreamId::new(3), b"<Order/>".to_vec(), None),
                contract: contract.map(str::to_string),
            }],
            MessageContext::new(),
            MessageTreatment::default(),
        )
    }

    fn identifier() -> Contract {
        Contract::new([
            ("partner-x-orders-v2", "partner-x"),
            ("partner-y-invoices", "partner-y"),
        ])
    }

    #[test]
    fn the_party_the_bound_contract_names_is_presented_as_a_detected_claim() {
        let claim = identifier()
            .identify(&message(Some("partner-x-orders-v2")))
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "partner-x");
        assert_eq!(claim.established, Established::Detected);
        assert_eq!(claim.layer(), Layer::Message);
        assert_eq!(claim.mechanism.name(), "contract");
        assert_eq!(
            claim.evidence,
            vec![(CONTRACT.to_string(), "partner-x-orders-v2".to_string())]
        );
    }

    #[test]
    fn a_section_bound_to_no_contract_presents_nothing() {
        assert!(
            identifier()
                .identify(&message(None))
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn a_contract_the_mapping_does_not_name_presents_nothing() {
        // The binding is real; it just names nobody this node knows. Not an
        // error: the contract may be one agreed with no Party in particular.
        assert!(
            identifier()
                .identify(&message(Some("public-price-list")))
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn a_binding_without_a_name_is_an_error_and_not_an_absence() {
        let failure = identifier()
            .identify(&message(Some("  ")))
            .expect_err("no name");

        assert!(failure.message.contains("no name"), "{failure}");
    }

    #[test]
    fn a_message_with_no_sections_presents_nothing() {
        let message = Message::received(
            MessageId::new(1),
            Vec::<MessageSection>::new(),
            MessageContext::new(),
            MessageTreatment::default(),
        );

        assert!(identifier().identify(&message).expect("read").is_none());
    }
}
