// secret-dialog-macos — native macOS dialog: hidden field + eye button to reveal.
// Usage: secret-dialog-macos "Title" "Message" [--visible] [--timeout 300]
// stdout: the typed text (no trailing newline). exit 0 ok · 2 cancelled · 3 timed out · 4 empty
// Never prints anything else. Built by install.sh; used through bin/secret-dialog.
import AppKit

var title = "Secret"
var message = ""
var startVisible = false
var timeout: Double = 300
var positional: [String] = []
var args = Array(CommandLine.arguments.dropFirst())
while !args.isEmpty {
    let a = args.removeFirst()
    switch a {
    case "--visible": startVisible = true
    case "--timeout": if let v = args.first, let d = Double(v) { timeout = d; args.removeFirst() }
    default: positional.append(a)
    }
}
if positional.count > 0 { title = positional[0] }
if positional.count > 1 { message = positional[1] }

let app = NSApplication.shared
app.setActivationPolicy(.accessory)

// Without an Edit menu, an AppKit app gets no ⌘V/⌘C/⌘X/⌘A key equivalents —
// the field would only accept typing or a right-click → Paste.
let mainMenu = NSMenu()
let editItem = NSMenuItem()
let editMenu = NSMenu(title: "Edit")
editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
editItem.submenu = editMenu
mainMenu.addItem(editItem)
app.mainMenu = mainMenu

let alert = NSAlert()
alert.messageText = title
alert.informativeText = message
alert.alertStyle = .warning
alert.addButton(withTitle: "OK")
alert.addButton(withTitle: "Cancel")

let width: CGFloat = 360
let box = NSView(frame: NSRect(x: 0, y: 0, width: width, height: 52))

let secure = NSSecureTextField(frame: NSRect(x: 0, y: 26, width: width - 40, height: 24))
let plain = NSTextField(frame: NSRect(x: 0, y: 26, width: width - 40, height: 24))
plain.isHidden = true
secure.placeholderString = "paste here"
plain.placeholderString = "paste here"
for f in [secure, plain] as [NSTextField] {
    f.isEditable = true; f.isSelectable = true; f.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
}

let eye = NSButton(frame: NSRect(x: width - 34, y: 26, width: 34, height: 24))
eye.bezelStyle = .rounded
eye.setButtonType(.toggle)
eye.image = NSImage(systemSymbolName: "eye", accessibilityDescription: "show")
eye.alternateImage = NSImage(systemSymbolName: "eye.slash", accessibilityDescription: "hide")
eye.toolTip = "Show / hide"

let hiddenHint = "Hidden field. Click the eye to check what you pasted."
let visibleHint = "VISIBLE. Click the eye to hide it again."
let hint = NSTextField(labelWithString: hiddenHint)
hint.frame = NSRect(x: 0, y: 2, width: width, height: 18)
hint.font = NSFont.systemFont(ofSize: 11)
hint.textColor = .secondaryLabelColor

final class Toggler: NSObject {
    var showing = false
    @objc func toggle(_ sender: NSButton) {
        showing.toggle()
        if showing { plain.stringValue = secure.stringValue } else { secure.stringValue = plain.stringValue }
        secure.isHidden = showing
        plain.isHidden = !showing
        hint.stringValue = showing ? visibleHint : hiddenHint
        (showing ? plain : secure).window?.makeFirstResponder(showing ? plain : secure)
    }
}
let toggler = Toggler()
eye.target = toggler
eye.action = #selector(Toggler.toggle(_:))

box.addSubview(secure); box.addSubview(plain); box.addSubview(eye); box.addSubview(hint)
alert.accessoryView = box
if startVisible { toggler.toggle(eye); eye.state = .on }

var timedOut = false
let timer = Timer.scheduledTimer(withTimeInterval: timeout, repeats: false) { _ in
    timedOut = true
    app.abortModal()
}
RunLoop.main.add(timer, forMode: .modalPanel)

app.activate(ignoringOtherApps: true)
alert.window.initialFirstResponder = secure
let response = alert.runModal()
timer.invalidate()

if timedOut { exit(3) }
if response != .alertFirstButtonReturn { exit(2) }
let value = toggler.showing ? plain.stringValue : secure.stringValue
if value.isEmpty { exit(4) }
FileHandle.standardOutput.write(value.data(using: .utf8)!)
exit(0)
