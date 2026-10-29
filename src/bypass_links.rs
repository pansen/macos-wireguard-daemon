//! LAN bypass links (see `doc/lan-bypass-links.md`): while the Mac is attached
//! to a link's anchor network, the link's prefixes stay off the tunnel.
//!
//! This module holds what the CLI, the daemon and the userspace helper share:
//! the link type with its wire and disk format, parsing of the CLI syntax, and
//! the one validation function. The routing decision itself lives in the
//! helper (`userspace_helper::macos::routes`).
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Set by the daemon when it spawns the helper: the validated links of the
/// connection as a JSON array. Absent means no links.
pub const ENV: &str = "WGD_BYPASS_LINKS";

/// Upper bounds on what one connection may store. Far above any real setup;
/// they keep a request from an unprivileged caller cheap to process.
pub const MAX_LINKS: usize = 32;
pub const MAX_PREFIXES_PER_LINK: usize = 64;

/// While `anchor` is a connected subnet, the `bypass` prefixes stay off the
/// tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BypassLink {
    /// Canonical network address, any family.
    pub anchor: IpNet,
    pub bypass: BypassTargets,
}

/// What a link takes off the tunnel. Phase 1 knows explicit prefixes only;
/// the wildcard of phase 1b (`*`, all AllowedIPs) becomes a second variant
/// and only needs [`BypassTargets::matches`] to learn about it.
///
/// Untagged, so the stored and wire form is the plain JSON array of CIDR
/// strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BypassTargets {
    /// Canonical, non-empty, each one an AllowedIPs entry once validated.
    Prefixes(Vec<IpNet>),
}

impl BypassTargets {
    /// The explicit prefixes, for display and validation.
    #[must_use]
    pub fn prefixes(&self) -> &[IpNet] {
        match self {
            Self::Prefixes(prefixes) => prefixes,
        }
    }

    /// Whether the route for `destination` (canonical) is taken off the
    /// tunnel: it equals a bypass prefix or lies inside one, like the routes
    /// the connected-subnet exclusion removes. A narrower AllowedIPs entry
    /// inside a bypassed prefix would otherwise keep part of it on the tunnel.
    #[must_use]
    pub fn matches(&self, destination: &IpNet) -> bool {
        match self {
            Self::Prefixes(prefixes) => prefixes.iter().any(|prefix| prefix.contains(destination)),
        }
    }
}

impl BypassLink {
    #[must_use]
    pub fn new(anchor: IpNet, bypass: Vec<IpNet>) -> Self {
        Self {
            anchor,
            bypass: BypassTargets::Prefixes(bypass),
        }
    }

    /// `<anchor>=<prefix>[,<prefix>...]`, the syntax of `--set-link`.
    #[must_use]
    pub fn spec(&self) -> String {
        let prefixes: Vec<String> = self
            .bypass
            .prefixes()
            .iter()
            .map(ToString::to_string)
            .collect();
        format!("{}={}", self.anchor, prefixes.join(","))
    }
}

/// Why a link is rejected. The messages are user-facing: `connection config`
/// prints them as they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    Syntax {
        spec: String,
    },
    Cidr {
        spec: String,
        value: String,
    },
    Empty {
        anchor: IpNet,
    },
    TooManyLinks,
    TooManyPrefixes {
        anchor: IpNet,
    },
    /// The anchor must be a network the VPN config routes, so that it is
    /// exactly the LAN the existing exclusion takes off the tunnel.
    AnchorNotInAllowedIps {
        anchor: IpNet,
    },
    SameAsAnchor {
        anchor: IpNet,
        prefix: IpNet,
    },
    NotInAllowedIps {
        anchor: IpNet,
        prefix: IpNet,
    },
    InsideBroaderEntry {
        anchor: IpNet,
        prefix: IpNet,
        covering: IpNet,
    },
    FullTunnel {
        anchor: IpNet,
        prefix: IpNet,
        default: IpNet,
        family: &'static str,
    },
}

impl LinkError {
    /// The anchor of the link the error is about, if it is about one.
    #[must_use]
    pub fn anchor(&self) -> Option<IpNet> {
        match self {
            Self::Syntax { .. } | Self::Cidr { .. } | Self::TooManyLinks => None,
            Self::Empty { anchor }
            | Self::TooManyPrefixes { anchor }
            | Self::AnchorNotInAllowedIps { anchor }
            | Self::SameAsAnchor { anchor, .. }
            | Self::NotInAllowedIps { anchor, .. }
            | Self::InsideBroaderEntry { anchor, .. }
            | Self::FullTunnel { anchor, .. } => Some(*anchor),
        }
    }

    /// What is wrong, without the "link <anchor>:" lead-in of [`Display`].
    ///
    /// [`Display`]: std::fmt::Display
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Syntax { spec } => format!(
                "invalid link {spec:?}: expected <anchor>=<prefix>[,<prefix>...], for example 10.66.77.0/24=192.168.188.1/32"
            ),
            Self::Cidr { spec, value } => format!(
                "invalid CIDR {value:?} in link {spec:?} (a single host is written with /32 or /128)"
            ),
            Self::TooManyLinks => format!("too many links (at most {MAX_LINKS})"),
            Self::Empty { .. } => "no bypass prefix".to_string(),
            Self::TooManyPrefixes { .. } => {
                format!("too many bypass prefixes (at most {MAX_PREFIXES_PER_LINK})")
            }
            Self::AnchorNotInAllowedIps { anchor } => format!(
                "the anchor {anchor} is not an AllowedIPs entry; it must be a network the VPN config routes, the LAN the LAN exclusion already takes off the tunnel"
            ),
            Self::SameAsAnchor { prefix, .. } => format!(
                "bypass prefix {prefix} is the anchor itself, which is already kept off the tunnel while the Mac is attached to it"
            ),
            Self::NotInAllowedIps { prefix, .. } => format!(
                "{prefix} is not an AllowedIPs entry, so there is no tunnel route to remove"
            ),
            Self::InsideBroaderEntry {
                prefix, covering, ..
            } => format!(
                "{prefix} lies inside the broader AllowedIPs entry {covering}; taking its own route away does not help, the covering route still captures it"
            ),
            Self::FullTunnel {
                prefix,
                default,
                family,
                ..
            } => format!(
                "AllowedIPs contains {default}, so every {family} address goes through the tunnel and {prefix} cannot be taken off it"
            ),
        }
    }
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.anchor() {
            Some(anchor) => write!(f, "link {anchor}: {}", self.reason()),
            None => f.write_str(&self.reason()),
        }
    }
}

impl std::error::Error for LinkError {}

/// A CIDR whose host bits were set and have been cleared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostBitsCleared {
    pub given: IpNet,
    pub canonical: IpNet,
}

/// Parse one `--set-link` or `--add-link` value. Returns the canonical link plus every CIDR whose
/// host bits had to be cleared, so the caller can report them once.
pub fn parse_link_spec(spec: &str) -> Result<(BypassLink, Vec<HostBitsCleared>), LinkError> {
    let syntax = || LinkError::Syntax {
        spec: spec.to_string(),
    };
    let (anchor, prefixes) = spec.split_once('=').ok_or_else(syntax)?;
    let mut cleared = Vec::new();
    let mut parse = |value: &str| -> Result<IpNet, LinkError> {
        let value = value.trim();
        let given: IpNet = value.parse().map_err(|_| LinkError::Cidr {
            spec: spec.to_string(),
            value: value.to_string(),
        })?;
        let canonical = given.trunc();
        if canonical != given {
            cleared.push(HostBitsCleared { given, canonical });
        }
        Ok(canonical)
    };
    let anchor = parse(anchor)?;
    let mut bypass = Vec::new();
    for value in prefixes.split(',').filter(|value| !value.trim().is_empty()) {
        let prefix = parse(value)?;
        if !bypass.contains(&prefix) {
            bypass.push(prefix);
        }
    }
    if bypass.is_empty() {
        return Err(syntax());
    }
    Ok((BypassLink::new(anchor, bypass), cleared))
}

/// Clear host bits and drop repeated prefixes. Applied to everything that
/// arrives over the wire, so a hand-written request cannot store a link the
/// helper would compare wrongly.
#[must_use]
pub fn canonical_link(link: &BypassLink) -> BypassLink {
    let mut bypass: Vec<IpNet> = Vec::new();
    for prefix in link.bypass.prefixes() {
        let prefix = prefix.trunc();
        if !bypass.contains(&prefix) {
            bypass.push(prefix);
        }
    }
    BypassLink::new(link.anchor.trunc(), bypass)
}

/// Result of checking a set of links against the current AllowedIPs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkReport {
    /// Canonical links that validate, in the order given.
    pub valid: Vec<BypassLink>,
    /// Canonical links that do not, with the first reason each fails.
    pub invalid: Vec<(BypassLink, LinkError)>,
}

/// Check `links` against `allowed_ips` (the connection's AllowedIPs, all
/// peers). A link is valid as a whole or not at all.
///
/// Phase 1 only removes routes the tunnel owns, so every bypass prefix must
/// equal an AllowedIPs entry once host bits are cleared. A prefix that is not
/// listed, one inside a broader entry and any prefix under a default route of
/// its family each get their own error.
#[must_use]
pub fn validate_links(links: &[BypassLink], allowed_ips: &[IpNet]) -> LinkReport {
    let mut report = LinkReport::default();
    for (link, verdict) in check_links(links, allowed_ips) {
        match verdict {
            Ok(()) => report.valid.push(link),
            Err(error) => report.invalid.push((link, error)),
        }
    }
    report
}

/// [`validate_links`] without the split: every canonical link with its
/// verdict, in the order given.
#[must_use]
pub fn check_links(
    links: &[BypassLink],
    allowed_ips: &[IpNet],
) -> Vec<(BypassLink, Result<(), LinkError>)> {
    let allowed: Vec<IpNet> = allowed_ips.iter().map(IpNet::trunc).collect();
    links
        .iter()
        .enumerate()
        .map(|(index, link)| {
            let link = canonical_link(link);
            let verdict = if index >= MAX_LINKS {
                Err(LinkError::TooManyLinks)
            } else {
                check_link(&link, &allowed)
            };
            (link, verdict)
        })
        .collect()
}

/// All-or-nothing form for `connection config`: the canonical links, or the
/// first error.
pub fn validate_links_strict(
    links: &[BypassLink],
    allowed_ips: &[IpNet],
) -> Result<Vec<BypassLink>, LinkError> {
    let report = validate_links(links, allowed_ips);
    match report.invalid.into_iter().next() {
        Some((_, error)) => Err(error),
        None => Ok(report.valid),
    }
}

fn check_link(link: &BypassLink, allowed: &[IpNet]) -> Result<(), LinkError> {
    let anchor = link.anchor;
    let prefixes = link.bypass.prefixes();
    if prefixes.is_empty() {
        return Err(LinkError::Empty { anchor });
    }
    if prefixes.len() > MAX_PREFIXES_PER_LINK {
        return Err(LinkError::TooManyPrefixes { anchor });
    }
    check_anchor(anchor, allowed)?;
    for &prefix in prefixes {
        check_prefix(anchor, prefix, allowed)?;
    }
    Ok(())
}

/// The anchor must equal an AllowedIPs entry (`allowed` canonical): the
/// network whose attachment activates the link is then exactly the LAN the
/// existing exclusion takes off the tunnel.
fn check_anchor(anchor: IpNet, allowed: &[IpNet]) -> Result<(), LinkError> {
    if allowed.contains(&anchor) {
        Ok(())
    } else {
        Err(LinkError::AnchorNotInAllowedIps { anchor })
    }
}

fn check_prefix(anchor: IpNet, prefix: IpNet, allowed: &[IpNet]) -> Result<(), LinkError> {
    if prefix == anchor {
        return Err(LinkError::SameAsAnchor { anchor, prefix });
    }
    let same_family = |entry: &&IpNet| entry.addr().is_ipv4() == prefix.addr().is_ipv4();
    if let Some(&default) = allowed
        .iter()
        .filter(same_family)
        .find(|entry| entry.prefix_len() == 0)
    {
        return Err(LinkError::FullTunnel {
            anchor,
            prefix,
            default,
            family: if prefix.addr().is_ipv4() {
                "IPv4"
            } else {
                "IPv6"
            },
        });
    }
    // A strictly shorter entry keeps capturing the prefix once its own route is
    // gone, whether or not the prefix is listed itself.
    if let Some(&covering) = allowed
        .iter()
        .filter(same_family)
        .find(|entry| entry.prefix_len() < prefix.prefix_len() && entry.contains(&prefix))
    {
        return Err(LinkError::InsideBroaderEntry {
            anchor,
            prefix,
            covering,
        });
    }
    if !allowed.contains(&prefix) {
        return Err(LinkError::NotInAllowedIps { anchor, prefix });
    }
    Ok(())
}

/// What [`prune_links`] took out of a link set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removed {
    pub anchor: IpNet,
    /// The dropped prefix; `None` when the whole link went.
    pub prefix: Option<IpNet>,
    pub reason: LinkError,
}

impl std::fmt::Display for Removed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.prefix {
            Some(prefix) => write!(
                f,
                "link {}: dropped prefix {prefix}: {}",
                self.anchor,
                self.reason.reason()
            ),
            None => write!(f, "link {}: dropped: {}", self.anchor, self.reason.reason()),
        }
    }
}

/// `stored` with `added` folded in, for `connection config --add-link`. The
/// prefixes of an added link join the stored link with the same anchor, missing
/// ones appended in order; a link for a new anchor goes at the end.
#[must_use]
pub fn merge_links(stored: &[BypassLink], added: &[BypassLink]) -> Vec<BypassLink> {
    let mut merged: Vec<BypassLink> = stored.iter().map(canonical_link).collect();
    for link in added.iter().map(canonical_link) {
        match merged.iter_mut().find(|known| known.anchor == link.anchor) {
            Some(known) => {
                let mut prefixes = known.bypass.prefixes().to_vec();
                for &prefix in link.bypass.prefixes() {
                    if !prefixes.contains(&prefix) {
                        prefixes.push(prefix);
                    }
                }
                *known = BypassLink::new(known.anchor, prefixes);
            }
            None => merged.push(link),
        }
    }
    merged
}

/// Result of [`prune_links`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pruned {
    /// Canonical links that validate against the AllowedIPs.
    pub links: Vec<BypassLink>,
    pub removed: Vec<Removed>,
}

/// Bring `links` in line with new AllowedIPs (after `connection refresh` or
/// when `add --force` replaces a connection): bypass prefixes that no longer
/// validate are dropped, and a link goes entirely when its anchor no longer
/// validates or no prefix is left.
#[must_use]
pub fn prune_links(links: &[BypassLink], allowed_ips: &[IpNet]) -> Pruned {
    let allowed: Vec<IpNet> = allowed_ips.iter().map(IpNet::trunc).collect();
    let mut pruned = Pruned::default();
    for link in links.iter().map(canonical_link) {
        let anchor = link.anchor;
        if let Err(reason) = check_anchor(anchor, &allowed) {
            pruned.removed.push(Removed {
                anchor,
                prefix: None,
                reason,
            });
            continue;
        }
        let mut kept = Vec::new();
        for &prefix in link.bypass.prefixes() {
            match check_prefix(anchor, prefix, &allowed) {
                Ok(()) => kept.push(prefix),
                Err(reason) => pruned.removed.push(Removed {
                    anchor,
                    prefix: Some(prefix),
                    reason,
                }),
            }
        }
        if kept.is_empty() {
            pruned.removed.push(Removed {
                anchor,
                prefix: None,
                reason: LinkError::Empty { anchor },
            });
        } else {
            pruned.links.push(BypassLink::new(anchor, kept));
        }
    }
    pruned
}

/// Completion candidates for the value of `--set-link` and `--add-link`
/// (`<anchor>=<prefix>[,...]`)
/// given the AllowedIPs of the connection it is for.
///
/// Without `=` the candidates are the anchors, written with the `=` that comes
/// next. After `=` they are the bypass prefixes that would still validate for
/// that anchor and are not in the list yet, and each candidate repeats what
/// was typed before the last `,`. Every candidate starts with `current`.
#[must_use]
pub fn link_completions(current: &str, allowed_ips: &[IpNet]) -> Vec<String> {
    let canonical: Vec<IpNet> = allowed_ips.iter().map(IpNet::trunc).collect();
    let mut entries: Vec<IpNet> = Vec::new();
    for &entry in &canonical {
        // A default route is neither an anchor nor a bypass prefix.
        if entry.prefix_len() > 0 && !entries.contains(&entry) {
            entries.push(entry);
        }
    }
    let Some((anchor, rest)) = current.split_once('=') else {
        return entries
            .iter()
            .map(|entry| format!("{entry}="))
            .filter(|candidate| candidate.starts_with(current))
            .collect();
    };
    let done = rest.rsplit_once(',').map(|(done, _)| done);
    let listed: Vec<&str> = done
        .map(|done| done.split(',').collect())
        .unwrap_or_default();
    let lead = match done {
        Some(done) => format!("{anchor}={done},"),
        None => format!("{anchor}="),
    };
    let Ok(anchor_net) = anchor.parse::<IpNet>().map(|net| net.trunc()) else {
        return Vec::new();
    };
    if check_anchor(anchor_net, &canonical).is_err() {
        return Vec::new();
    }
    entries
        .iter()
        .filter(|entry| {
            !listed.contains(&entry.to_string().as_str())
                && check_prefix(anchor_net, **entry, &canonical).is_ok()
        })
        .map(|entry| format!("{lead}{entry}"))
        .filter(|candidate| candidate.starts_with(current))
        .collect()
}

/// The value of [`ENV`] for these (validated) links.
#[must_use]
pub fn to_env_value(links: &[BypassLink]) -> String {
    serde_json::to_string(links).expect("links serialize")
}

/// Parse the value of [`ENV`]. The daemon wrote it, so a failure is a bug and
/// the helper treats it as a startup error.
pub fn from_env_value(value: &str) -> Result<Vec<BypassLink>, serde_json::Error> {
    serde_json::from_str(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(value: &str) -> IpNet {
        value.parse().unwrap()
    }

    fn nets(values: &[&str]) -> Vec<IpNet> {
        values.iter().map(|value| net(value)).collect()
    }

    fn link(anchor: &str, bypass: &[&str]) -> BypassLink {
        BypassLink::new(net(anchor), nets(bypass))
    }

    const HOME_ALLOWED: &[&str] = &[
        "192.168.168.0/24",
        "100.64.1.0/24",
        "10.66.77.0/24",
        "192.168.188.1/32",
    ];

    #[test]
    fn merge_joins_prefixes_of_a_known_anchor_and_appends_new_anchors() {
        let stored = [link("10.66.77.0/24", &["192.168.188.1/32"])];
        let added = [
            link("10.66.77.0/24", &["192.168.188.1/32", "100.64.1.0/24"]),
            link("172.16.5.0/24", &["192.168.9.1/32"]),
        ];
        assert_eq!(
            merge_links(&stored, &added),
            vec![
                link("10.66.77.0/24", &["192.168.188.1/32", "100.64.1.0/24"]),
                link("172.16.5.0/24", &["192.168.9.1/32"]),
            ]
        );
    }

    #[test]
    fn parses_the_cli_syntax() {
        let (parsed, cleared) =
            parse_link_spec("10.66.77.0/24=192.168.188.1/32,192.168.188.50/32").unwrap();
        assert_eq!(
            parsed,
            link("10.66.77.0/24", &["192.168.188.1/32", "192.168.188.50/32"])
        );
        assert!(cleared.is_empty());
        assert_eq!(
            parsed.spec(),
            "10.66.77.0/24=192.168.188.1/32,192.168.188.50/32"
        );
    }

    #[test]
    fn host_bits_are_cleared_and_reported() {
        let (parsed, cleared) = parse_link_spec("10.66.77.5/24=192.168.188.0/24").unwrap();
        assert_eq!(parsed.anchor, net("10.66.77.0/24"));
        assert_eq!(
            cleared,
            vec![HostBitsCleared {
                given: net("10.66.77.5/24"),
                canonical: net("10.66.77.0/24"),
            }]
        );
        let (parsed, cleared) = parse_link_spec("fd00::1/64=fd01::7/64").unwrap();
        assert_eq!(parsed, link("fd00::/64", &["fd01::/64"]));
        assert_eq!(cleared.len(), 2);
    }

    #[test]
    fn repeated_prefixes_collapse() {
        let (parsed, _) =
            parse_link_spec("10.0.0.0/24=192.168.1.1/32,192.168.1.1/32,192.168.1.0/24").unwrap();
        assert_eq!(
            parsed.bypass.prefixes(),
            nets(&["192.168.1.1/32", "192.168.1.0/24"]).as_slice()
        );
    }

    #[test]
    fn malformed_specs_are_rejected() {
        for spec in [
            "",
            "10.66.77.0/24",
            "10.66.77.0/24=",
            "10.66.77.0/24=,",
            "=192.168.188.1/32",
        ] {
            assert!(parse_link_spec(spec).is_err(), "{spec:?}");
        }
        assert!(matches!(
            parse_link_spec("10.66.77.0/24=192.168.188.1"),
            Err(LinkError::Cidr { .. })
        ));
        assert!(matches!(
            parse_link_spec("10.66.77.0/33=192.168.188.1/32"),
            Err(LinkError::Cidr { .. })
        ));
    }

    #[test]
    fn the_example_from_the_spec_validates() {
        let links = vec![link("10.66.77.0/24", &["192.168.188.1/32"])];
        let report = validate_links(&links, &nets(HOME_ALLOWED));
        assert_eq!(report.valid, links);
        assert!(report.invalid.is_empty());
    }

    #[test]
    fn a_prefix_that_is_not_in_allowed_ips_is_rejected() {
        let links = vec![link("10.66.77.0/24", &["192.168.188.2/32"])];
        let error = validate_links_strict(&links, &nets(HOME_ALLOWED)).unwrap_err();
        assert_eq!(
            error,
            LinkError::NotInAllowedIps {
                anchor: net("10.66.77.0/24"),
                prefix: net("192.168.188.2/32"),
            }
        );
        assert!(error.to_string().contains("not an AllowedIPs entry"));
    }

    #[test]
    fn a_prefix_inside_a_broader_entry_is_rejected() {
        let allowed = nets(&["192.168.0.0/16", "10.66.77.0/24"]);
        let links = vec![link("10.66.77.0/24", &["192.168.188.1/32"])];
        let error = validate_links_strict(&links, &allowed).unwrap_err();
        assert_eq!(
            error,
            LinkError::InsideBroaderEntry {
                anchor: net("10.66.77.0/24"),
                prefix: net("192.168.188.1/32"),
                covering: net("192.168.0.0/16"),
            }
        );
        assert!(error.to_string().contains("broader AllowedIPs entry"));
    }

    #[test]
    fn a_listed_prefix_inside_a_broader_entry_is_rejected_too() {
        // Removing the /32 route would send the traffic into the /16 route,
        // which is the tunnel's as well.
        let allowed = nets(&["192.168.0.0/16", "192.168.188.1/32", "10.66.77.0/24"]);
        let links = vec![link("10.66.77.0/24", &["192.168.188.1/32"])];
        assert!(matches!(
            validate_links_strict(&links, &allowed),
            Err(LinkError::InsideBroaderEntry { .. })
        ));
        // A narrower sibling does not matter.
        let allowed = nets(&["192.168.188.0/24", "192.168.188.1/32", "10.66.77.0/24"]);
        let links = vec![link("10.66.77.0/24", &["192.168.188.0/24"])];
        assert!(validate_links_strict(&links, &allowed).is_ok());
    }

    #[test]
    fn any_prefix_is_rejected_under_a_default_route_of_its_family() {
        let links = vec![link("10.66.77.0/24", &["192.168.188.1/32"])];
        for default in ["0.0.0.0/0", "::/0"] {
            let allowed = nets(&[default, "192.168.188.1/32", "10.66.77.0/24"]);
            let result = validate_links_strict(&links, &allowed);
            if default == "0.0.0.0/0" {
                assert!(matches!(result, Err(LinkError::FullTunnel { .. })));
                assert!(result.unwrap_err().to_string().contains("0.0.0.0/0"));
            } else {
                // An IPv6 default route does not capture an IPv4 prefix.
                assert!(result.is_ok());
            }
        }
        let v6 = vec![link("fd00::/64", &["fd01::1/128"])];
        assert!(matches!(
            validate_links_strict(&v6, &nets(&["::/0", "fd01::1/128", "fd00::/64"])),
            Err(LinkError::FullTunnel { family: "IPv6", .. })
        ));
    }

    #[test]
    fn the_anchor_must_be_an_allowed_ips_entry() {
        let links = vec![link("172.16.0.0/24", &["192.168.188.1/32"])];
        let error = validate_links_strict(&links, &nets(HOME_ALLOWED)).unwrap_err();
        assert_eq!(
            error,
            LinkError::AnchorNotInAllowedIps {
                anchor: net("172.16.0.0/24")
            }
        );
        let text = error.to_string();
        assert!(text.starts_with("link 172.16.0.0/24: "), "{text}");
        assert!(text.contains("anchor"), "{text}");

        // Inside a broader entry is not an entry either: the LAN exclusion
        // would take the /8, not the /24.
        let allowed = nets(&["10.0.0.0/8", "192.168.188.1/32"]);
        let links = vec![link("10.66.77.0/24", &["192.168.188.1/32"])];
        assert!(matches!(
            validate_links_strict(&links, &allowed),
            Err(LinkError::AnchorNotInAllowedIps { .. })
        ));

        // Host bits in the AllowedIPs line do not matter.
        let allowed = nets(&["10.66.77.9/24", "192.168.188.1/32"]);
        assert!(validate_links_strict(&links, &allowed).is_ok());
    }

    #[test]
    fn prune_keeps_what_still_validates_and_reports_the_rest() {
        let links = vec![
            // Both prefixes survive.
            link("10.66.77.0/24", &["192.168.188.1/32", "192.168.168.0/24"]),
            // One prefix goes, one stays.
            link("100.64.1.0/24", &["192.168.188.1/32", "192.168.99.1/32"]),
            // Every prefix goes: the whole link goes.
            link("192.168.168.0/24", &["192.168.99.1/32"]),
            // Anchor gone: the whole link goes, whatever its prefixes.
            link("172.16.0.0/24", &["192.168.188.1/32"]),
        ];
        let pruned = prune_links(&links, &nets(HOME_ALLOWED));
        assert_eq!(
            pruned.links,
            vec![
                link("10.66.77.0/24", &["192.168.188.1/32", "192.168.168.0/24"]),
                link("100.64.1.0/24", &["192.168.188.1/32"]),
            ]
        );
        let removed: Vec<(String, Option<String>)> = pruned
            .removed
            .iter()
            .map(|r| (r.anchor.to_string(), r.prefix.map(|p| p.to_string())))
            .collect();
        assert_eq!(
            removed,
            vec![
                (
                    "100.64.1.0/24".to_string(),
                    Some("192.168.99.1/32".to_string())
                ),
                (
                    "192.168.168.0/24".to_string(),
                    Some("192.168.99.1/32".to_string())
                ),
                ("192.168.168.0/24".to_string(), None),
                ("172.16.0.0/24".to_string(), None),
            ]
        );
        assert!(matches!(
            pruned.removed[3].reason,
            LinkError::AnchorNotInAllowedIps { .. }
        ));
        // What is left validates, and pruning it again changes nothing.
        let report = validate_links(&pruned.links, &nets(HOME_ALLOWED));
        assert!(report.invalid.is_empty());
        assert_eq!(
            prune_links(&pruned.links, &nets(HOME_ALLOWED)).removed,
            vec![]
        );
    }

    #[test]
    fn prune_after_allowed_ips_change_names_the_reason() {
        let links = vec![link("10.66.77.0/24", &["192.168.188.1/32"])];
        // The server now routes the whole /16 instead of the host.
        let pruned = prune_links(&links, &nets(&["10.66.77.0/24", "192.168.0.0/16"]));
        assert!(pruned.links.is_empty());
        let lines: Vec<String> = pruned.removed.iter().map(ToString::to_string).collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("link 10.66.77.0/24: dropped prefix 192.168.188.1/32: "));
        assert!(lines[0].contains("192.168.0.0/16"));
        assert_eq!(lines[1], "link 10.66.77.0/24: dropped: no bypass prefix");
        // A refresh that changes nothing relevant prunes nothing.
        assert_eq!(
            prune_links(&links, &nets(HOME_ALLOWED)),
            Pruned {
                links: links.clone(),
                removed: vec![]
            }
        );
    }

    #[test]
    fn completion_offers_anchors_without_an_equals_sign() {
        let allowed = nets(&[
            "192.168.168.0/24",
            "10.66.77.0/24",
            "192.168.188.1/24",
            "fd00::/64",
            "0.0.0.0/1",
            "::/0",
        ]);
        let all = link_completions("", &allowed);
        assert_eq!(
            all,
            vec![
                "192.168.168.0/24=",
                "10.66.77.0/24=",
                "192.168.188.0/24=",
                "fd00::/64=",
                "0.0.0.0/1=",
            ]
        );
        assert_eq!(link_completions("192.", &allowed).len(), 2);
        assert_eq!(link_completions("fd", &allowed), vec!["fd00::/64="]);
        assert!(link_completions("172.", &allowed).is_empty());
    }

    #[test]
    fn completion_offers_prefixes_after_the_equals_sign() {
        let allowed = nets(HOME_ALLOWED);
        // Anchor typed, nothing after `=`: every other entry.
        assert_eq!(
            link_completions("10.66.77.0/24=", &allowed),
            vec![
                "10.66.77.0/24=192.168.168.0/24",
                "10.66.77.0/24=100.64.1.0/24",
                "10.66.77.0/24=192.168.188.1/32",
            ]
        );
        // Partial prefix.
        assert_eq!(
            link_completions("10.66.77.0/24=192.168.18", &allowed),
            vec!["10.66.77.0/24=192.168.188.1/32"]
        );
        // Second prefix: the first is not offered again, and is kept.
        assert_eq!(
            link_completions("10.66.77.0/24=192.168.188.1/32,1", &allowed),
            vec![
                "10.66.77.0/24=192.168.188.1/32,192.168.168.0/24",
                "10.66.77.0/24=192.168.188.1/32,100.64.1.0/24",
            ]
        );
        // Nothing left to add.
        assert!(link_completions(
            "10.66.77.0/24=192.168.188.1/32,192.168.168.0/24,100.64.1.0/24,",
            &allowed
        )
        .is_empty());
    }

    #[test]
    fn completion_skips_prefixes_that_would_not_validate() {
        // 192.168.188.1/32 sits inside the /16, so no link could bypass it.
        let allowed = nets(&[
            "10.66.77.0/24",
            "192.168.0.0/16",
            "192.168.188.1/32",
            "fd00::/64",
        ]);
        assert_eq!(
            link_completions("10.66.77.0/24=", &allowed),
            vec!["10.66.77.0/24=192.168.0.0/16", "10.66.77.0/24=fd00::/64"]
        );
        // IPv6 entries complete like any other.
        assert_eq!(
            link_completions("fd00::/64=", &allowed),
            vec!["fd00::/64=10.66.77.0/24", "fd00::/64=192.168.0.0/16",]
        );
        // A default route lets no prefix through, and is not offered.
        let full = nets(&["0.0.0.0/0", "10.66.77.0/24", "192.168.188.1/32"]);
        assert!(link_completions("10.66.77.0/24=", &full).is_empty());
        // An anchor not in AllowedIPs offers no prefixes.
        assert!(link_completions("172.16.0.0/24=", &allowed).is_empty());
        assert!(link_completions("not-a-cidr=", &allowed).is_empty());
    }

    #[test]
    fn a_prefix_equal_to_its_anchor_is_rejected() {
        let links = vec![link("10.66.77.0/24", &["10.66.77.0/24"])];
        assert!(matches!(
            validate_links_strict(&links, &nets(HOME_ALLOWED)),
            Err(LinkError::SameAsAnchor { .. })
        ));
    }

    #[test]
    fn host_bits_in_stored_links_do_not_defeat_the_comparison() {
        let links = vec![BypassLink::new(
            net("10.66.77.9/24"),
            nets(&["192.168.188.1/32"]),
        )];
        let report = validate_links(&links, &nets(&["192.168.188.1/32", "10.66.77.7/24"]));
        assert_eq!(
            report.valid,
            vec![link("10.66.77.0/24", &["192.168.188.1/32"])]
        );
    }

    #[test]
    fn one_bad_prefix_invalidates_only_its_own_link() {
        let good = link("10.66.77.0/24", &["192.168.188.1/32"]);
        let bad = link("100.64.1.0/24", &["192.168.188.1/32", "192.168.99.1/32"]);
        let report = validate_links(&[bad.clone(), good.clone()], &nets(HOME_ALLOWED));
        assert_eq!(report.valid, vec![good]);
        assert_eq!(report.invalid.len(), 1);
        assert_eq!(report.invalid[0].0, bad);
        assert!(matches!(
            report.invalid[0].1,
            LinkError::NotInAllowedIps { .. }
        ));
    }

    #[test]
    fn empty_and_oversized_links_are_rejected() {
        let allowed = nets(HOME_ALLOWED);
        assert!(matches!(
            validate_links_strict(&[link("10.66.77.0/24", &[])], &allowed),
            Err(LinkError::Empty { .. })
        ));
        let many = vec![link("10.66.77.0/24", &["192.168.188.1/32"]); MAX_LINKS + 1];
        let report = validate_links(&many, &allowed);
        assert_eq!(report.valid.len(), MAX_LINKS);
        assert_eq!(report.invalid.len(), 1);
    }

    #[test]
    fn serde_form_is_a_plain_array_of_cidr_strings() {
        let original = link("10.66.77.0/24", &["192.168.188.1/32", "fd01::/64"]);
        let json = serde_json::to_value(&original).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "anchor": "10.66.77.0/24",
                "bypass": ["192.168.188.1/32", "fd01::/64"],
            })
        );
        assert_eq!(
            serde_json::from_value::<BypassLink>(json).unwrap(),
            original
        );
    }

    #[test]
    fn env_value_round_trips_and_rejects_garbage() {
        let links = vec![
            link("10.66.77.0/24", &["192.168.188.1/32"]),
            link("fd00::/64", &["fd01::/64"]),
        ];
        assert_eq!(from_env_value(&to_env_value(&links)).unwrap(), links);
        assert_eq!(from_env_value("[]").unwrap(), Vec::new());
        assert!(from_env_value("").is_err());
        assert!(from_env_value("not json").is_err());
        assert!(from_env_value(r#"[{"anchor":"10.0.0.0/33","bypass":[]}]"#).is_err());
    }

    #[test]
    fn bypass_targets_match_by_containment() {
        let targets = BypassTargets::Prefixes(nets(&["192.168.188.0/24", "fd01::/64"]));
        for inside in [
            "192.168.188.0/24",
            "192.168.188.7/32",
            "192.168.188.128/25",
            "fd01::/64",
            "fd01::7/128",
        ] {
            assert!(targets.matches(&net(inside)), "{inside}");
        }
        // Broader, beside, and another family do not.
        for outside in [
            "192.168.0.0/16",
            "192.168.189.0/24",
            "192.168.187.255/32",
            "fd01::/32",
            "fd02::/64",
            "0.0.0.0/0",
        ] {
            assert!(!targets.matches(&net(outside)), "{outside}");
        }
    }
}
