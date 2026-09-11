#!/usr/bin/env python3
"""secret-dialog-gtk — native GNOME/GTK dialog: hidden field + eye (peek icon) to reveal.

Usage: secret-dialog-gtk.py "Title" "Message" [--visible] [--timeout 300]
stdout: the typed text (no trailing newline). exit 0 ok · 2 cancelled · 3 timed out · 4 empty · 5 no GTK
GTK4: Gtk.PasswordEntry with show_peek_icon (the real GNOME eye).
GTK3 fallback: Gtk.Entry with a toggling secondary icon.
Needs python3-gi (PyGObject), installed by default on GNOME desktops.
UNTESTED by the author on a real Linux desktop — please open an issue with results.
"""
import sys

args = sys.argv[1:]
title, message, visible, timeout = "Secret", "", False, 300
pos = []
while args:
    a = args.pop(0)
    if a == "--visible":
        visible = True
    elif a == "--timeout" and args:
        timeout = int(float(args.pop(0)))
    else:
        pos.append(a)
if pos:
    title = pos[0]
if len(pos) > 1:
    message = pos[1]

try:
    import gi
except ImportError:
    sys.exit(5)

result = {"code": 2, "text": ""}


def run_gtk4():
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk, GLib

    app = Gtk.Application(application_id="dev.claude1password.secretdialog")

    def on_activate(app):
        win = Gtk.ApplicationWindow(application=app, title=title)
        win.set_default_size(420, -1)
        win.set_resizable(False)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        for m in (12, 12, 12, 12):
            pass
        box.set_margin_top(14); box.set_margin_bottom(14); box.set_margin_start(14); box.set_margin_end(14)
        lbl = Gtk.Label(label=message, wrap=True, xalign=0)
        box.append(lbl)
        if visible:
            entry = Gtk.Entry()
        else:
            entry = Gtk.PasswordEntry()
            entry.set_show_peek_icon(True)  # the eye
        entry.set_hexpand(True)
        box.append(entry)
        hint = Gtk.Label(label="" if visible else "Hidden field. Click the eye to check what you pasted.", xalign=0)
        hint.add_css_class("dim-label")
        box.append(hint)
        btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, halign=Gtk.Align.END)
        cancel = Gtk.Button(label="Cancel")
        ok = Gtk.Button(label="OK")
        ok.add_css_class("suggested-action")
        btns.append(cancel); btns.append(ok)
        box.append(btns)
        win.set_child(box)

        def finish(code):
            result["code"] = code
            result["text"] = entry.get_text()
            win.close()

        ok.connect("clicked", lambda *_: finish(0))
        cancel.connect("clicked", lambda *_: finish(2))
        entry.connect("activate", lambda *_: finish(0))
        win.connect("close-request", lambda *_: (result.__setitem__("code", result["code"] if result["code"] != 2 or result["text"] else 2), False)[1])
        GLib.timeout_add_seconds(max(1, timeout), lambda: (finish(3), False)[1])
        win.present()
        entry.grab_focus()

    app.connect("activate", on_activate)
    app.run([])


def run_gtk3():
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk, GLib

    dlg = Gtk.Dialog(title=title)
    dlg.set_default_size(420, -1)
    dlg.set_keep_above(True)
    dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
    dlg.add_button("OK", Gtk.ResponseType.OK)
    dlg.set_default_response(Gtk.ResponseType.OK)
    area = dlg.get_content_area()
    area.set_spacing(10); area.set_border_width(14)
    lbl = Gtk.Label(label=message, xalign=0); lbl.set_line_wrap(True)
    area.add(lbl)
    entry = Gtk.Entry()
    entry.set_visibility(visible)
    entry.set_activates_default(True)
    if not visible:
        entry.set_icon_from_icon_name(Gtk.EntryIconPosition.SECONDARY, "view-reveal-symbolic")
        entry.set_icon_tooltip_text(Gtk.EntryIconPosition.SECONDARY, "Show / hide")

        def toggle(e, pos, ev):
            e.set_visibility(not e.get_visibility())
            e.set_icon_from_icon_name(Gtk.EntryIconPosition.SECONDARY,
                                      "view-conceal-symbolic" if e.get_visibility() else "view-reveal-symbolic")
        entry.connect("icon-press", toggle)
    area.add(entry)
    hint = Gtk.Label(label="" if visible else "Hidden field. Click the eye to check what you pasted.", xalign=0)
    hint.get_style_context().add_class("dim-label")
    area.add(hint)
    dlg.show_all()
    GLib.timeout_add_seconds(max(1, timeout), lambda: (dlg.response(Gtk.ResponseType.NONE), False)[1])
    resp = dlg.run()
    result["text"] = entry.get_text()
    result["code"] = 0 if resp == Gtk.ResponseType.OK else (3 if resp == Gtk.ResponseType.NONE else 2)
    dlg.destroy()


try:
    run_gtk4()
except (ValueError, ImportError):
    try:
        run_gtk3()
    except (ValueError, ImportError):
        sys.exit(5)

code, text = result["code"], result["text"]
if code == 0 and not text:
    code = 4
if code == 0:
    sys.stdout.write(text)
    sys.stdout.flush()
sys.exit(code)
