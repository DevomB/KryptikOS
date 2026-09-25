//! Zone visual identity: can the user tell every two border colours the
//! compositor draws apart, under each of four vision models?
//!
//! The `zoneid` binary audits the zone files in CI and searches for palettes
//! that pass (docs/architecture.md). kryptikd only checks the shape of the
//! `[ui]` keys; neither it nor the proxy uses this crate. The check is a floor
//! on a colour-difference metric, not a guarantee against confusion.
//!
//! | Channel | Shown by |
//! |---|---|
//! | `color` | the whole window border, drawn by dwl |
//! | `glyph`, `label` | the chrome, for the focused window |
//! | `pattern` | nothing yet: validated, given no weight |

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
