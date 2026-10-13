//! A zone's selection, served by the proxy among the zone's own clients: copy and paste inside a
//! zone, with nothing sent to the compositor or another zone. Only the client with the keyboard
//! copies, and a client is offered the selection just before the keyboard enters it, as the core
//! protocol has a compositor do (wl_data_device.selection). The broker stays the only channel
//! between zones.

use std::os::unix::io::OwnedFd;

/// What the zone's clients last copied: the session that holds the source, the
/// wl_data_source in that session's ids, and the types it offered.
#[derive(Debug)]
pub struct Selection {
    pub owner: u64,
    pub source: u32,
    pub mimes: Vec<String>,
}

/// What one session's messages ask of another, done by the main loop once every turn is over.
#[derive(Debug)]
pub enum Action {
    /// Offer the selection to the session's data devices, if its client still has the keyboard.
    Offer(u64),
    /// The session's source no longer holds the selection.
    Cancel(u64, u32),
    /// The session's source is to write its data of one type to the descriptor.
    Send(u64, u32, String, OwnedFd),
}

impl Action {
    pub fn session(&self) -> u64 {
        match self {
            Action::Offer(s) | Action::Cancel(s, _) | Action::Send(s, ..) => *s,
        }
    }
}

#[derive(Debug, Default)]
pub struct Clipboard {
    /// The session whose client the keyboard is in.
    pub focus: Option<u64>,
    pub selection: Option<Selection>,
    /// Counts selections: an offer made for an older one reads nothing.
    pub generation: u64,
    pub actions: Vec<Action>,
}

impl Clipboard {
    /// A copy, or none: the old source is cancelled unless it is set again, and the client with
    /// the keyboard is offered what is now the selection.
    pub fn set(&mut self, sel: Option<Selection>) {
        if let Some(old) = self.selection.take() {
            if !sel.as_ref().is_some_and(|s| s.owner == old.owner && s.source == old.source) {
                self.actions.push(Action::Cancel(old.owner, old.source));
            }
        }
        self.selection = sel;
        self.changed();
    }

    /// A source its client destroyed: if it held the selection, the zone has none.
    pub fn source_gone(&mut self, owner: u64, source: u32) {
        if self.selection.as_ref().is_some_and(|s| s.owner == owner && s.source == source) {
            self.selection = None;
            self.changed();
        }
    }

    /// A session ended: its selection and the keyboard's place with it, and what was asked of it.
    pub fn session_gone(&mut self, id: u64) {
        self.actions.retain(|a| a.session() != id);
        if self.focus == Some(id) {
            self.focus = None;
        }
        if self.selection.as_ref().is_some_and(|s| s.owner == id) {
            self.selection = None;
            self.changed();
        }
    }

    fn changed(&mut self) {
        self.generation += 1;
        if let Some(f) = self.focus {
            self.actions.push(Action::Offer(f));
        }
    }
}

#[cfg(test)]
mod tests;
