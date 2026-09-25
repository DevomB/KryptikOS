//! zoneid — Kryptik zone visual identity and the perceptual distinctness
//! invariant.
//!
//! docs/architecture.md states that per-zone visual identity is "load-bearing,
//! not decoration": if a user cannot tell at a glance which zone a password
//! prompt belongs to, compartmentalization has failed at the only layer that
//! matters. This crate is what makes that claim checkable instead of merely
//! asserted.
//!
//! It answers one question - *can a person tell these two border colours
//! apart?* - for every colour the compositor draws, under four vision models.
//! The `zoneid` binary asks it of the zone files in CI and searches for
//! palettes that pass. kryptikd checks only the shape of a zone's `[ui]`
//! keys; neither it nor the proxy depends on this crate.
//!
//! # The channels
//!
//! | Channel | Shown by |
//! |---|---|
//! | `color` | the whole window border, drawn by dwl |
//! | `glyph`, `label` | the chrome, for the focused window |
//! | `pattern` | nothing yet: validated, given no weight |
//!
//! Colour is the channel seen without looking for it, which is why its floor
//! holds under colour-vision deficiency and not only normal vision.
//!
//! # What this crate does NOT do
//!
//! It does not decide whether a *user* is confused - it decides whether two
//! identities are distinguishable in principle, under a stated vision model,
//! by a colour-difference metric. Real confusion also involves habit, screen
//! calibration, ambient light and haste. The invariant here is a floor, not a
//! guarantee.

pub mod color;
pub mod cvd;
pub mod distinct;
pub mod identity;
pub mod palette;
pub mod toml;
pub mod zones;

pub use color::{contrast_ratio, delta_e, ciede2000, Lab, Srgb};
pub use cvd::{simulate, Vision};
pub use distinct::{Collision, Report, Thresholds};
pub use identity::{Channel, Pattern, ZoneIdentity};
