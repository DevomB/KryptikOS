# Input methods

Typing Chinese, Japanese or Korean takes an input method: a program between
the keyboard and the window that turns keys into words and offers a list of
candidates. Kryptik has none. Layouts switch, and compose and dead keys work
in each client through xkbcommon's compose tables, but no zone can type a
CJK script. The laptop design chose one input method per zone, inside it,
offered the input-method protocol by its proxy and never the virtual
keyboard ([laptop](laptop.md#input-methods)), and left open whether an input
method works without the virtual keyboard. It does not. This design settles
what replaces that rule. [ADR-028](../decisions.md) decides it: none for
1.0, then one per zone, its virtual keyboard bound to the zone.

## Where things stand

- **Applications** speak `zwp_text_input_v3`. GTK 3's Wayland input module
  does, so Firefox does with nothing else in the zone, and so does Qt's
  Wayland platform.
- **The input method** speaks `zwp_input_method_v2`. The compositor tells it
  what the focused text field holds, it grabs the keyboard while a field
  has focus, and it commits text. The keys it lets pass (arrows, shortcuts,
  Enter outside a composition) it sends on through
  `zwp_virtual_keyboard_v1`, as a keyboard of its own.
- **fcitx5's** Wayland frontend starts its input-method server only when
  both globals are there (`WaylandIMServerV2::init`), and sends every key it
  lets pass through the virtual keyboard (`sendKeyToVK`). **IBus** has no
  `zwp_input_method_v2` frontend at all. Without a virtual keyboard, no
  input method works on a wlroots compositor.
- **dwl 0.8** has neither text input nor input methods. It has the virtual
  keyboard, and a virtual keyboard's keys pass through `keybinding()` as the
  real keyboard's do. Kryptik's proxies offer it to no zone.

## What a virtual keyboard can do

Its keys go wherever the keyboard focus is, and its keymap becomes the
seat's for whoever receives them. Offered to a zone as dwl has it, the zone
could type into another zone's window or the chrome, press the
compositor's own keys (Alt+Shift+l, the move gesture), and hand another
zone a keymap of its choosing.

## Options

- **No input method for 1.0.** As now: layouts and compose, no CJK input,
  and the guide says so.
- **One input method per zone, with a virtual keyboard bound to its
  zone.** The laptop design's choice, with its rule changed. A zone whose
  file asks for an input method (`[input] method = true`) is offered
  `zwp_text_input_manager_v3`, `zwp_input_method_manager_v2` and
  `zwp_virtual_keyboard_manager_v1` by its proxy. dwl knows each client's
  zone from the socket it came through
  ([compositor separation](compositor-separation.md)), and treats the
  zone's virtual keyboard as that zone's alone:
  - its keys reach a window only while a window of the same zone has the
    keyboard focus, and are dropped otherwise;
  - they never pass through the compositor's bindings;
  - its keymap reaches only that zone's windows;
  - the input method's keyboard grab holds only while that zone has focus,
    so the chrome's and other zones' keys never reach it;
  - a text field's state goes only to the input method of its own zone, and
    that method's commits only to that field;
  - dwl's own keys come first: `keybinding()` runs on the real keyboard's
    keys before an input method's grab sees them, so no zone's method sees
    or swallows Alt+Shift+l, the move gesture or any other compositor key;
  - its candidate window (`zwp_input_popup_surface_v2`) follows the rules
    for a zone's popups: placed and clipped inside its zone's window and
    frame, never drawn over the chrome or another zone's window.

  The virtual keyboard then does no more than the zone's own windows can:
  type into themselves.
- **One input method per zone, no virtual keyboard.** Not with fcitx5 or
  IBus. An input method of Kryptik's own would be new code in every zone,
  and a key it lets pass would be lost, or sent back by a protocol of
  Kryptik's.
- **One input method in zone 0 for every zone.** Rejected in the laptop
  design: it sees every zone's keys, and its dictionary links the zones.

## What it costs

- **dwl:** a relay between text input and the input method, as sway has
  (several hundred lines on wlroots' helpers for both protocols), keyed by
  zone, and the virtual keyboard's routing.
- **The proxy:** three more globals, for the zones that ask.
- **fcitx5 and its engines** (pinyin, anthy or mozc, hangul) in those zones,
  shipped as signed software images (ADR-015) rather than in the root, as
  most users need none. fcitx5 can leave D-Bus out (`ENABLE_DBUS`), which
  zones do not run.

## The decision

ADR-028 decides: for 1.0, no input method, and the guide says so. Then one
per zone, with the virtual keyboard bound to its zone as above, and fcitx5
delivered as a software image. That is the direction, not yet the code:
dwl's relay is weighed again when the work starts.

## Check, when it comes

`make gui-test`, with fcitx5 and a test engine in `work`:

- a key typed in a `work` window reaches the engine, and its commit lands
  in that window;
- while the chrome or a `personal` window has focus, the engine gets no
  key, and keys sent through `work`'s virtual keyboard reach no window;
- Alt+Shift+l sent through `work`'s virtual keyboard locks nothing, and
  from the real keyboard it locks the screen while `work`'s engine holds
  the grab;
- a candidate list opened near the edge of a `work` window stays inside its
  frame;
- a zone that did not ask is offered none of the three globals;
- a layout set in the session still reaches every zone's client in its
  keymap.

## Not covered

- On-screen keyboards, the virtual keyboard's other use.
- Emoji pickers and handwriting.
