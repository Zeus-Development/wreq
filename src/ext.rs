//! Extensions specific to the HTTP/2 protocol.

use crate::hpack::BytesStr;

use bytes::Bytes;
use std::fmt;

/// Represents the `:protocol` pseudo-header used by
/// the [Extended CONNECT Protocol].
///
/// [Extended CONNECT Protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
#[derive(Clone, Eq, PartialEq)]
pub struct Protocol {
    value: BytesStr,
}

impl Protocol {
    /// Converts a static string to a protocol name.
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            value: BytesStr::from_static(value),
        }
    }

    /// Returns a str representation of the header.
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    pub(crate) fn try_from(bytes: Bytes) -> Result<Self, std::str::Utf8Error> {
        Ok(Self {
            value: BytesStr::try_from(bytes)?,
        })
    }
}

impl<'a> From<&'a str> for Protocol {
    fn from(value: &'a str) -> Self {
        Self {
            value: BytesStr::from(value),
        }
    }
}

impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}

// VIPER-PATCH(h2-stream-priority): a request's RFC 9218 section 4.1
// urgency, which a client that also sends RFC 9113 section 5.3.2 priority
// fields maps to its HEADERS frame's weight and dependency, and which a
// dispatcher may order requests by before their streams are opened.
/// A request's urgency (RFC 9218 section 4.1): 0, the most urgent, to 7;
/// 3 by default. Put in a request's extensions, it chooses the request's
/// HEADERS priority under [`UrgencyPriorities`]
/// ([`client::Builder::urgency_priorities`](crate::client::Builder::urgency_priorities)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Urgency(u8);

impl Urgency {
    /// RFC 9218's default urgency, 3.
    pub const DEFAULT: Self = Self(3);

    /// The urgency `value`, or `None` above 7.
    pub const fn new(value: u8) -> Option<Self> {
        if value <= 7 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Its value, 0 to 7.
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl Default for Urgency {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The RFC 9113 section 5.3.2 priority each request's HEADERS frame
/// carries, chosen by the request's [`Urgency`] (the default one when its
/// extensions have none), in place of the connection's one
/// `headers_stream_dependency`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UrgencyPriorities {
    /// The weight of each urgency, from 0 to 7, in
    /// [`StreamDependency`](crate::frame::StreamDependency)'s form: 0 to 255
    /// for the weights 1 to 256.
    pub weights: [u8; 8],
    /// Whether each dependency is exclusive.
    pub exclusive: bool,
    /// The stream each request's stream depends on.
    pub parent: UrgencyParent,
}

/// The stream a request's stream depends on, under [`UrgencyPriorities`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UrgencyParent {
    /// Stream 0, the root of the tree.
    Root,
    /// The newest stream the connection opened, of those not closed, at the
    /// nearest urgency at or above the request's: one of its own urgency if
    /// any is open, else of the next more urgent one, and so on; stream 0
    /// when there is none.
    NearestOpen,
}
