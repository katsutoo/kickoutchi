use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use thiserror::Error;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::display::{is_default_ignorable, sanitize};
use crate::model::Protocol;
use crate::observation::{EndpointIdentity, Ipv6Scope};

pub(crate) const LABEL_SELECTORS_MAX: usize = 256;
pub(crate) const LABEL_TEXT_MAX_BYTES: usize = 128;
pub(crate) const LABEL_DISPLAY_MAX_COLUMNS: usize = 32;
pub(crate) const SELECTOR_ADDRESS_MAX_BYTES: usize = 64;

#[derive(Debug)]
pub(crate) struct LabelInput {
    pub(crate) protocol: String,
    pub(crate) address: String,
    pub(crate) port: u64,
    pub(crate) scope_id: Option<u64>,
    pub(crate) label: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct LabelRegistry {
    exact: HashMap<EndpointIdentity, Arc<str>>,
    wildcard: HashMap<(Protocol, u16), Arc<str>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum LabelError {
    #[error("ports has {actual} selectors, maximum is {max}")]
    TooManySelectors { actual: usize, max: usize },
    #[error("ports[{index}].{field} {detail}")]
    InvalidField {
        index: usize,
        field: &'static str,
        detail: &'static str,
    },
    #[error("ports[{index}] duplicates selector ports[{first_index}]")]
    DuplicateSelector { index: usize, first_index: usize },
}

impl LabelRegistry {
    pub(crate) fn from_inputs(inputs: Vec<LabelInput>) -> Result<Self, LabelError> {
        if inputs.len() > LABEL_SELECTORS_MAX {
            return Err(LabelError::TooManySelectors {
                actual: inputs.len(),
                max: LABEL_SELECTORS_MAX,
            });
        }

        let mut registry = Self {
            exact: HashMap::with_capacity(inputs.len()),
            wildcard: HashMap::with_capacity(inputs.len()),
        };
        let mut exact_indexes = HashMap::with_capacity(inputs.len());
        let mut wildcard_indexes = HashMap::with_capacity(inputs.len());
        for (index, input) in inputs.into_iter().enumerate() {
            let LabelInput {
                protocol,
                address,
                port,
                scope_id,
                label,
            } = input;
            let protocol = parse_protocol(index, &protocol)?;
            let port = parse_port(index, port)?;
            validate_label(index, &label)?;

            if address == "*" {
                if scope_id.is_some() {
                    return Err(invalid(
                        index,
                        "scope_id",
                        "is valid only with an exact IPv6 address",
                    ));
                }
                let key = (protocol, port);
                if let Some(&first_index) = wildcard_indexes.get(&key) {
                    return Err(LabelError::DuplicateSelector { index, first_index });
                }
                wildcard_indexes.insert(key, index);
                registry.wildcard.insert(key, Arc::from(label));
                continue;
            }

            let endpoint = parse_exact_endpoint(index, protocol, &address, scope_id, port)?;
            if let Some(&first_index) = exact_indexes.get(&endpoint) {
                return Err(LabelError::DuplicateSelector { index, first_index });
            }
            exact_indexes.insert(endpoint.clone(), index);
            registry.exact.insert(endpoint, Arc::from(label));
        }
        Ok(registry)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.exact.len() + self.wildcard.len()
    }

    pub(crate) fn resolve(&self, endpoint: &EndpointIdentity) -> Option<&str> {
        self.exact
            .get(endpoint)
            .or_else(|| self.wildcard.get(&(endpoint.protocol, endpoint.port.get())))
            .map(AsRef::as_ref)
    }

    pub(crate) fn resolve_parts(
        &self,
        protocol: Protocol,
        address: IpAddr,
        port: u16,
        ipv6_scope: Option<Ipv6Scope>,
    ) -> Option<&str> {
        let address = normalize_ip_address(address);
        let ipv6_scope = address.is_ipv6().then_some(ipv6_scope).flatten();
        let endpoint =
            EndpointIdentity::new(protocol, address, u32::from(port), ipv6_scope).ok()?;
        self.resolve(&endpoint)
    }
}

fn parse_protocol(index: usize, protocol: &str) -> Result<Protocol, LabelError> {
    match protocol {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        _ => Err(invalid(index, "protocol", "must be exactly tcp or udp")),
    }
}

fn parse_port(index: usize, port: u64) -> Result<u16, LabelError> {
    u16::try_from(port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid(index, "port", "must be in 1..=65535"))
}

fn parse_exact_endpoint(
    index: usize,
    protocol: Protocol,
    address: &str,
    scope_id: Option<u64>,
    port: u16,
) -> Result<EndpointIdentity, LabelError> {
    if address.len() > SELECTOR_ADDRESS_MAX_BYTES {
        return Err(invalid(index, "address", "exceeds the 64-byte limit"));
    }
    let address = address
        .parse::<IpAddr>()
        .map(normalize_ip_address)
        .map_err(|_| invalid(index, "address", "must be a literal IP address or *"))?;
    let ipv6_scope = match (address, scope_id) {
        (IpAddr::V4(_), None) => None,
        (IpAddr::V4(_), Some(_)) => {
            return Err(invalid(
                index,
                "scope_id",
                "is invalid when the normalized address is IPv4",
            ));
        }
        (IpAddr::V6(_), None) => Some(Ipv6Scope::Unscoped),
        (IpAddr::V6(_), Some(scope_id)) => {
            let scope_id = u32::try_from(scope_id)
                .ok()
                .and_then(NonZeroU32::new)
                .ok_or_else(|| invalid(index, "scope_id", "must be in 1..=4294967295"))?;
            Some(Ipv6Scope::InterfaceIndex(scope_id))
        }
    };
    EndpointIdentity::new(protocol, address, u32::from(port), ipv6_scope)
        .map_err(|_| invalid(index, "address", "does not form a valid endpoint selector"))
}

fn validate_label(index: usize, label: &str) -> Result<(), LabelError> {
    if label.is_empty() || label.chars().all(char::is_whitespace) {
        return Err(invalid(index, "label", "must contain visible text"));
    }
    if label.trim_matches(char::is_whitespace) != label {
        return Err(invalid(
            index,
            "label",
            "must not have leading or trailing whitespace",
        ));
    }
    if label.len() > LABEL_TEXT_MAX_BYTES {
        return Err(invalid(index, "label", "exceeds the 128-byte limit"));
    }
    if label.chars().any(is_forbidden_label_scalar) {
        return Err(invalid(
            index,
            "label",
            "contains a control or default-ignorable Unicode scalar",
        ));
    }
    Ok(())
}

const fn invalid(index: usize, field: &'static str, detail: &'static str) -> LabelError {
    LabelError::InvalidField {
        index,
        field,
        detail,
    }
}

pub(crate) fn normalize_ip_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(address) => IpAddr::V4(address),
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
    }
}

pub(crate) fn label_display_text(label: &str) -> String {
    let sanitized = sanitize(label);
    if sanitized.width() <= LABEL_DISPLAY_MAX_COLUMNS {
        return sanitized;
    }

    let content_columns = LABEL_DISPLAY_MAX_COLUMNS - '…'.width().unwrap_or(1);
    let mut clipped = String::with_capacity(sanitized.len().min(LABEL_TEXT_MAX_BYTES));
    let mut columns = 0usize;
    for ch in sanitized.chars() {
        let width = ch.width().unwrap_or(0);
        let Some(next) = columns.checked_add(width) else {
            break;
        };
        if next > content_columns {
            break;
        }
        clipped.push(ch);
        columns = next;
    }
    clipped.push('…');
    clipped
}

fn is_forbidden_label_scalar(ch: char) -> bool {
    ch.is_control() || is_default_ignorable(ch)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use unicode_width::UnicodeWidthStr;

    use super::{
        LABEL_DISPLAY_MAX_COLUMNS, LABEL_SELECTORS_MAX, LabelError, LabelInput, LabelRegistry,
        SELECTOR_ADDRESS_MAX_BYTES, label_display_text,
    };
    use crate::model::Protocol;
    use crate::observation::{EndpointIdentity, Ipv6Scope};

    fn input(protocol: &str, address: &str, port: u64, label: &str) -> LabelInput {
        LabelInput {
            protocol: protocol.to_owned(),
            address: address.to_owned(),
            port,
            scope_id: None,
            label: label.to_owned(),
        }
    }

    fn endpoint(protocol: Protocol, address: IpAddr, port: u32) -> EndpointIdentity {
        let scope = address.is_ipv6().then_some(Ipv6Scope::Unscoped);
        EndpointIdentity::new(protocol, address, port, scope).unwrap()
    }

    #[test]
    fn exact_match_precedes_wildcard_and_protocol_port_remain_distinct() {
        let registry = LabelRegistry::from_inputs(vec![
            input("tcp", "*", 3000, "wild"),
            input("tcp", "127.0.0.1", 3000, "exact"),
            input("udp", "*", 3000, "udp"),
        ])
        .unwrap();

        assert_eq!(
            registry.resolve(&endpoint(
                Protocol::Tcp,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                3000,
            )),
            Some("exact")
        );
        assert_eq!(
            registry.resolve(&endpoint(
                Protocol::Tcp,
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                3000,
            )),
            Some("wild")
        );
        assert_eq!(
            registry.resolve(&endpoint(
                Protocol::Udp,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                3000,
            )),
            Some("udp")
        );
        assert_eq!(
            registry.resolve(&endpoint(
                Protocol::Tcp,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                3001,
            )),
            None
        );
    }

    #[test]
    fn exact_labels_keep_ipv4_and_ipv6_endpoints_separate() {
        let registry = LabelRegistry::from_inputs(vec![
            input("tcp", "0.0.0.0", 8080, "ipv4"),
            input("tcp", "::", 8080, "ipv6"),
        ])
        .unwrap();

        assert_eq!(
            registry.resolve(&endpoint(
                Protocol::Tcp,
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                8080,
            )),
            Some("ipv4")
        );
        assert_eq!(
            registry.resolve(&endpoint(
                Protocol::Tcp,
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                8080,
            )),
            Some("ipv6")
        );
    }

    #[test]
    fn duplicate_exact_and_wildcard_selectors_report_the_first_index() {
        for inputs in [
            vec![
                input("tcp", "127.0.0.1", 80, "first"),
                input("tcp", "127.0.0.1", 80, "second"),
            ],
            vec![
                input("udp", "*", 53, "first"),
                input("udp", "*", 53, "second"),
            ],
        ] {
            assert_eq!(
                LabelRegistry::from_inputs(inputs).unwrap_err(),
                LabelError::DuplicateSelector {
                    index: 1,
                    first_index: 0,
                }
            );
        }
    }

    #[test]
    fn ipv6_scope_matching_is_exact_and_wildcard_ignores_scope() {
        let mut scoped = input("tcp", "fe80::1", 8080, "scoped");
        scoped.scope_id = Some(7);
        let registry =
            LabelRegistry::from_inputs(vec![scoped, input("tcp", "*", 8080, "wild")]).unwrap();
        let scoped_endpoint = EndpointIdentity::new(
            Protocol::Tcp,
            IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap()),
            8080,
            Some(Ipv6Scope::interface_index(7).unwrap()),
        )
        .unwrap();
        let unavailable = EndpointIdentity::new(
            Protocol::Tcp,
            scoped_endpoint.address,
            8080,
            Some(Ipv6Scope::Unavailable),
        )
        .unwrap();

        assert_eq!(registry.resolve(&scoped_endpoint), Some("scoped"));
        assert_eq!(registry.resolve(&unavailable), Some("wild"));
    }

    #[test]
    fn mapped_ipv6_duplicates_canonical_ipv4_and_rejects_scope() {
        let duplicate = LabelRegistry::from_inputs(vec![
            input("tcp", "127.0.0.1", 80, "v4"),
            input("tcp", "::ffff:127.0.0.1", 80, "mapped"),
        ]);
        assert!(matches!(
            duplicate,
            Err(LabelError::DuplicateSelector {
                index: 1,
                first_index: 0
            })
        ));

        let mut scoped = input("tcp", "::ffff:127.0.0.1", 80, "mapped");
        scoped.scope_id = Some(1);
        assert!(matches!(
            LabelRegistry::from_inputs(vec![scoped]),
            Err(LabelError::InvalidField {
                field: "scope_id",
                ..
            })
        ));

        let registry =
            LabelRegistry::from_inputs(vec![input("tcp", "127.0.0.1", 80, "v4")]).unwrap();
        assert_eq!(
            registry.resolve_parts(
                Protocol::Tcp,
                IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()),
                80,
                Some(Ipv6Scope::Unavailable),
            ),
            Some("v4")
        );
    }

    #[test]
    fn selector_count_accepts_maximum_and_rejects_first_excess() {
        let maximum = (1..=LABEL_SELECTORS_MAX)
            .map(|port| input("tcp", "*", u64::try_from(port).unwrap(), "service"))
            .collect();
        assert_eq!(LabelRegistry::from_inputs(maximum).unwrap().len(), 256);

        let excess = (1..=LABEL_SELECTORS_MAX + 1)
            .map(|port| input("tcp", "*", u64::try_from(port).unwrap(), "service"))
            .collect();
        assert!(matches!(
            LabelRegistry::from_inputs(excess),
            Err(LabelError::TooManySelectors { actual: 257, .. })
        ));
    }

    #[test]
    fn selector_fields_reject_invalid_boundaries() {
        for (selector, field) in [
            (input("TCP", "*", 80, "service"), "protocol"),
            (input("tcp", "localhost", 80, "service"), "address"),
            (input("tcp", &"1".repeat(65), 80, "service"), "address"),
            (input("tcp", "*", 0, "service"), "port"),
            (input("tcp", "*", 65_536, "service"), "port"),
        ] {
            assert!(matches!(
                LabelRegistry::from_inputs(vec![selector]),
                Err(LabelError::InvalidField {
                    field: actual,
                    ..
                }) if actual == field
            ));
        }

        for scope_id in [0, u64::from(u32::MAX) + 1] {
            let mut selector = input("tcp", "::1", 80, "service");
            selector.scope_id = Some(scope_id);
            assert!(matches!(
                LabelRegistry::from_inputs(vec![selector]),
                Err(LabelError::InvalidField {
                    field: "scope_id",
                    ..
                })
            ));
        }

        let mut maximum_scope = input("tcp", "fe80::1", u64::from(u16::MAX), "service");
        maximum_scope.scope_id = Some(u64::from(u32::MAX));
        assert!(LabelRegistry::from_inputs(vec![maximum_scope]).is_ok());

        let at_address_cap = LabelRegistry::from_inputs(vec![input(
            "tcp",
            &"1".repeat(SELECTOR_ADDRESS_MAX_BYTES),
            80,
            "service",
        )])
        .unwrap_err()
        .to_string();
        assert!(at_address_cap.contains("must be a literal IP address"));
        let above_address_cap = LabelRegistry::from_inputs(vec![input(
            "tcp",
            &"1".repeat(SELECTOR_ADDRESS_MAX_BYTES + 1),
            80,
            "service",
        )])
        .unwrap_err()
        .to_string();
        assert!(above_address_cap.contains("exceeds the 64-byte limit"));
    }

    #[test]
    fn hostile_and_boundary_labels_are_validated_without_reflection() {
        let exact = "x".repeat(128);
        assert!(LabelRegistry::from_inputs(vec![input("tcp", "*", 80, &exact)]).is_ok());
        for label in [
            "",
            "   ",
            " leading",
            "trailing ",
            &"x".repeat(129),
            "escape\u{1b}[2J",
            "bidi\u{202e}txt",
            "zero\u{200b}width",
            "soft\u{00ad}hyphen",
            "reserved\u{2065}",
        ] {
            let error = LabelRegistry::from_inputs(vec![input("tcp", "*", 80, label)])
                .expect_err("invalid label must be rejected");
            let message = error.to_string();
            assert!(message.starts_with("ports[0].label"), "{message}");
            assert!(!message.chars().any(super::is_forbidden_label_scalar));
        }
    }

    #[test]
    fn display_clipping_preserves_unicode_and_never_exceeds_32_columns() {
        let exact = "界".repeat(16);
        assert_eq!(label_display_text(&exact), exact);

        let clipped = label_display_text(&"界".repeat(17));
        assert!(clipped.ends_with('…'));
        assert!(clipped.width() <= LABEL_DISPLAY_MAX_COLUMNS);
        assert!(!clipped.contains('�'));

        let adjacent = label_display_text(&"x".repeat(LABEL_DISPLAY_MAX_COLUMNS + 1));
        assert_eq!(adjacent.width(), LABEL_DISPLAY_MAX_COLUMNS);
        assert!(adjacent.ends_with('…'));
    }
}
