//! zoneid — Kryptik zone visual identity and the perceptual distinctness
//! invariant.
//!
//! docs/architecture.md states that per-zone visual identity is "load-bearing,
//! not decoration": if a user cannot tell at a glance which zone a password
//! prompt belongs to, compartmentalization has failed at the only layer that
//! matters. This crate is what makes that claim checkable instead of merely
//! asserted.
//!
//! It answers one question - *can a human distinguish these two zones?* - and
//! answers it the same way for three different callers:
//!
//! * `kryptikd`, which refuses to load a zone set that fails (the enforcement
//!   point that actually matters);
//! * `kryptik-wlproxy`, which draws the identity and must agree with the
//!   enforcement about what it is drawing;
//! * CI, via the `zoneid` binary, which reports rather than refuses.
//!
//! # The model
//!
//! A zone identity carries four independent channels, because relying on one
//! is how the shipped palette ended up with two pairs of zones that are the
//! same colour to a colour-blind user:
//!
//! | Channel | Scope | Survives |
//! |---|---|---|
//! | `color` | global - the whole window edge | trichromatic vision only |
//! | `pattern` | global - the whole window edge | CVD, monochrome, a photo of the screen |
//! | `glyph` | point - the titlebar tag | everything, if you look at it |
//! | `label` | point - the titlebar tag | everything, if you read it |
//!
//! The global/point distinction is the one that matters and the one that is
//! easy to miss. Colour and pattern are perceived without looking directly at
//! them; glyph and label require attention. A design with only point channels
//! technically identifies every window and still fails the "at a glance"
//! standard, which is the standard the threat model actually relies on.
//!
//! # What this crate does NOT do
//!
//! It does not decide whether a *user* is confused - it decides whether two
//! identities are distinguishable in principle, under a stated vision model,
//! by a colour-difference metric. Real confusion also involves habit, screen
//! calibration, ambient light and haste. The invariant here is a floor, not a
//! guarantee, and docs/gui-isolation.md says so in the same words.

pub mod color;
pub mod cvd;
pub mod distinct;
pub mod identity;
pub mod palette;
pub mod toml;

pub use color::{contrast_ratio, delta_e, ciede2000, Lab, Srgb};
pub use cvd::{simulate, Vision};
pub use distinct::{Collision, Report, Thresholds};
pub use identity::{Channel, Pattern, ZoneIdentity};
