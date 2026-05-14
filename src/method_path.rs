//! `MethodPath` — validated dotted method-path newtype.
//!
//! Identifies a method on the call graph: `<activation>.<method>` or
//! `<activation>.<child>.<method>` for nested activations. Used by
//! [`crate::forward::CallSite`] to name the callee being dispatched to,
//! by audit records to attribute scope checks, and (per AUTHZ-S01) by
//! protected-method declarations.
//!
//! Per the strong-typing rule (AUTHZ-S01 §1): we do not pass bare `String`
//! method names through framework signatures. `MethodPath` wraps an
//! invariant-bearing string — the constructor validates that the path
//! matches the segment grammar before producing a value.
//!
//! # Grammar
//!
//! ```text
//! MethodPath ::= Segment ("." Segment)+
//! Segment    ::= [a-z] [a-z0-9_]*
//! ```
//!
//! - At least two segments (so a method always has an activation prefix).
//! - Segments are lowercase ASCII; underscores allowed inside, digits
//!   allowed after the first character.
//! - Wildcards (`*`) are NOT allowed in `MethodPath` — those belong on the
//!   scope grammar (AUTHZ-S01 §1).
//!
//! # Why this lives in `plexus-auth-core`
//!
//! `CallSite { caller: Principal, callee_method: MethodPath }` couples the
//! sealed `Principal` to the method path. Both need to live in the same
//! crate so the dispatch perimeter can construct them together without
//! cross-crate orphan-rule friction. The path's validation is mechanical
//! and does not consume any auth-bearing state, so colocating it here adds
//! no surface-area risk.
//!
//! # Coordination note (parallel work)
//!
//! The AUTHZ-CORE-3 capability-advertisement work also introduces a
//! `MethodPath` newtype in `capabilities.rs`. The two are intentionally
//! shape-compatible (same wire form, same grammar, same accessors) so the
//! eventual merge can collapse them into a single canonical type. AUTHLANG-2
//! lands this version on its branch to keep `CallSite`'s dependency
//! self-contained; the merge owner reconciles to one path.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A validated dotted method path, e.g. `solar.earth.luna.info`.
///
/// Constructed via [`MethodPath::try_new`] which enforces the segment
/// grammar. Once constructed, the inner string is immutable (no setter).
/// `as_str` exposes a borrow for display / matching.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MethodPath(String);

/// Reason a `MethodPath::try_new` call rejected its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodPathError {
    /// The string was empty.
    Empty,
    /// Fewer than two segments (e.g., `"login"` instead of `"auth.login"`).
    NotEnoughSegments,
    /// A segment was empty (e.g., `"foo..bar"`).
    EmptySegment,
    /// A segment began with a non-lowercase-alpha character.
    InvalidSegmentStart {
        /// Zero-based index of the offending segment.
        segment_index: usize,
    },
    /// A segment contained a character outside `[a-z0-9_]`.
    InvalidSegmentCharacter {
        /// Zero-based index of the offending segment.
        segment_index: usize,
        /// The offending character.
        character: char,
    },
}

impl fmt::Display for MethodPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "method path is empty"),
            Self::NotEnoughSegments => write!(
                f,
                "method path must have at least two segments (e.g., `<activation>.<method>`)"
            ),
            Self::EmptySegment => write!(f, "method path contains an empty segment"),
            Self::InvalidSegmentStart { segment_index } => write!(
                f,
                "segment {} must start with a lowercase ASCII letter",
                segment_index
            ),
            Self::InvalidSegmentCharacter {
                segment_index,
                character,
            } => write!(
                f,
                "segment {} contains invalid character `{}` (allowed: a-z, 0-9, _)",
                segment_index, character
            ),
        }
    }
}

impl std::error::Error for MethodPathError {}

impl MethodPath {
    /// Validate and construct a `MethodPath`.
    ///
    /// # Errors
    ///
    /// Returns a [`MethodPathError`] when the input does not satisfy the
    /// grammar documented at the module level.
    pub fn try_new(s: impl Into<String>) -> Result<Self, MethodPathError> {
        let s = s.into();
        if s.is_empty() {
            return Err(MethodPathError::Empty);
        }
        let segments: Vec<&str> = s.split('.').collect();
        if segments.len() < 2 {
            return Err(MethodPathError::NotEnoughSegments);
        }
        for (index, segment) in segments.iter().enumerate() {
            if segment.is_empty() {
                return Err(MethodPathError::EmptySegment);
            }
            let mut chars = segment.chars();
            let first = chars
                .next()
                .expect("segment non-empty checked above");
            if !first.is_ascii_lowercase() {
                return Err(MethodPathError::InvalidSegmentStart {
                    segment_index: index,
                });
            }
            for ch in chars {
                let ok = ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_';
                if !ok {
                    return Err(MethodPathError::InvalidSegmentCharacter {
                        segment_index: index,
                        character: ch,
                    });
                }
            }
        }
        Ok(Self(s))
    }

    /// Borrow the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first segment (the activation namespace).
    pub fn activation(&self) -> &str {
        self.0
            .split('.')
            .next()
            .expect("constructor guarantees at least two segments")
    }

    /// The final segment (the method name).
    pub fn method(&self) -> &str {
        self.0
            .rsplit('.')
            .next()
            .expect("constructor guarantees at least two segments")
    }
}

impl fmt::Display for MethodPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_new_accepts_two_segment_path() {
        let p = MethodPath::try_new("auth.login").unwrap();
        assert_eq!(p.as_str(), "auth.login");
        assert_eq!(p.activation(), "auth");
        assert_eq!(p.method(), "login");
    }

    #[test]
    fn try_new_accepts_nested_path() {
        let p = MethodPath::try_new("solar.earth.luna.info").unwrap();
        assert_eq!(p.activation(), "solar");
        assert_eq!(p.method(), "info");
    }

    #[test]
    fn try_new_rejects_empty() {
        assert_eq!(MethodPath::try_new(""), Err(MethodPathError::Empty));
    }

    #[test]
    fn try_new_rejects_single_segment() {
        assert_eq!(
            MethodPath::try_new("login"),
            Err(MethodPathError::NotEnoughSegments)
        );
    }

    #[test]
    fn try_new_rejects_double_dot() {
        assert_eq!(
            MethodPath::try_new("auth..login"),
            Err(MethodPathError::EmptySegment)
        );
    }

    #[test]
    fn try_new_rejects_uppercase_start() {
        assert_eq!(
            MethodPath::try_new("Auth.login"),
            Err(MethodPathError::InvalidSegmentStart { segment_index: 0 })
        );
    }

    #[test]
    fn try_new_rejects_digit_start() {
        assert_eq!(
            MethodPath::try_new("auth.0bad"),
            Err(MethodPathError::InvalidSegmentStart { segment_index: 1 })
        );
    }

    #[test]
    fn try_new_rejects_invalid_character() {
        assert_eq!(
            MethodPath::try_new("auth.log-in"),
            Err(MethodPathError::InvalidSegmentCharacter {
                segment_index: 1,
                character: '-'
            })
        );
    }

    #[test]
    fn try_new_rejects_wildcard() {
        assert_eq!(
            MethodPath::try_new("auth.*"),
            Err(MethodPathError::InvalidSegmentStart { segment_index: 1 })
        );
    }

    #[test]
    fn display_round_trips() {
        let p = MethodPath::try_new("a.b.c").unwrap();
        assert_eq!(format!("{}", p), "a.b.c");
    }
}
