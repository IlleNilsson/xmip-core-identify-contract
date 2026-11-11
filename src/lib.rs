#![forbid(unsafe_code)]

//! Identify by contract: the Contract the first section is bound to, read
//! out of what is there and proving nothing.
//!
//! A binding is a statement about the content's shape, and anyone who can
//! produce the shape can produce the binding, so it names no Party: the
//! claim is the Contract's name, *detected*. Who the content is from is what
//! its sender proved (the owner, 2026-11-10: a Party only from what the
//! sender proved). Where a Contract is agreed with a Party, `authorize/contract`
//! compares that Party with the one the sender proved and refuses another,
//! once (ADR-0019, amendment 2026-11-11; ADR-0050 section 5).
//!
//! A section bound to no contract carries nothing this identifier
//! recognizes; a binding with no name is an error, not an absence.
//!
//! The interchange senders ADR-0050 lists beside this leaf — ISA06, UNB S002,
//! MSH-3 — are promoted by the EDI and HL7 content technologies and read by
//! `identify/message` under their promoted names; this leaf reads the
//! binding, not the envelope.

use identify::{IdentifyError, MessageIdentifier, Presented};
use message::Message;
use xcore::Mechanism;

/// Reads the Contract the first section is bound to.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Contract;

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

        Ok(Some(Presented::detected(self.mechanism(), contract)))
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

    #[test]
    fn the_bound_contract_is_a_detected_claim_and_names_no_party() {
        let claim = Contract
            .identify(&message(Some("party-x-orders-v2")))
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "party-x-orders-v2");
        assert_eq!(claim.established, Established::Detected);
        assert_eq!(claim.layer(), Layer::Message);
        assert_eq!(claim.mechanism.name(), "contract");
        assert!(claim.evidence.is_empty(), "{:?}", claim.evidence);
    }

    #[test]
    fn a_section_bound_to_no_contract_presents_nothing() {
        assert!(Contract.identify(&message(None)).expect("read").is_none());
    }

    #[test]
    fn a_binding_without_a_name_is_an_error_and_not_an_absence() {
        let failure = Contract
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

        assert!(Contract.identify(&message).expect("read").is_none());
    }
}
