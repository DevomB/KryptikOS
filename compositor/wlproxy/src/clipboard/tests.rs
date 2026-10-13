use super::*;

fn sel(owner: u64, source: u32) -> Option<Selection> {
    Some(Selection { owner, source, mimes: vec!["text/plain".into()], data: None })
}

fn kinds(c: &mut Clipboard) -> Vec<String> {
    c.actions.drain(..).map(|a| format!("{a:?}")).collect()
}

#[test]
fn a_new_copy_cancels_the_old_source_and_is_offered_to_the_keyboard() {
    let mut c = Clipboard { focus: Some(1), ..Clipboard::default() };
    c.set(sel(1, 7));
    assert_eq!(kinds(&mut c), ["Offer(1)"]);
    let g = c.generation;
    c.set(sel(2, 9));
    assert_eq!(kinds(&mut c), ["Cancel(1, 7)", "Offer(1)"]);
    assert_eq!(c.generation, g + 1, "an offer of the old selection reads nothing now");
    // The same source set again is not cancelled.
    c.set(sel(2, 9));
    assert_eq!(kinds(&mut c), ["Offer(1)"]);
    // Cleared: the old source is cancelled, and the keyboard's client hears there is none.
    c.set(None);
    assert_eq!(kinds(&mut c), ["Cancel(2, 9)", "Offer(1)"]);
    assert!(c.selection.is_none());
}

#[test]
fn nobody_is_offered_without_the_keyboard() {
    let mut c = Clipboard::default();
    c.set(sel(1, 7));
    assert!(c.actions.is_empty());
    assert!(c.selection.is_some());
}

#[test]
fn a_destroyed_source_ends_its_selection_only() {
    let mut c = Clipboard { focus: Some(2), ..Clipboard::default() };
    c.set(sel(1, 7));
    kinds(&mut c);
    c.source_gone(1, 8);
    c.source_gone(2, 7);
    assert!(c.actions.is_empty() && c.selection.is_some(), "another source, or the same id in another session");
    c.source_gone(1, 7);
    assert_eq!(kinds(&mut c), ["Offer(2)"]);
    assert!(c.selection.is_none());
}

#[test]
fn an_ended_session_takes_its_selection_focus_and_errands() {
    let mut c = Clipboard { focus: Some(1), ..Clipboard::default() };
    c.set(sel(1, 7));
    let (r, _w) = std::os::unix::net::UnixStream::pair().unwrap();
    c.actions.push(Action::Send(1, 7, "text/plain".into(), r.into()));
    c.session_gone(1);
    assert!(c.actions.is_empty(), "nothing is left for the ended session, nor any offer: {:?}", c.actions);
    assert!(c.selection.is_none() && c.focus.is_none());
    // Another session's selection outlives it.
    let mut c = Clipboard { focus: Some(1), ..Clipboard::default() };
    c.set(sel(2, 7));
    kinds(&mut c);
    c.session_gone(1);
    assert!(c.selection.is_some() && c.focus.is_none() && c.actions.is_empty());
}
