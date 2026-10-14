module github.com/bashhack/sesh

go 1.27.0

require (
	charm.land/bubbles/v2 v2.2.1
	charm.land/bubbletea/v2 v2.1.0
	charm.land/lipgloss/v2 v2.0.6
	github.com/BurntSushi/toml v1.6.0
	github.com/charmbracelet/x/ansi v0.11.9
	github.com/makiuchi-d/gozxing v0.1.2-0.20250720151325-95e256b768ac
	github.com/pquerna/otp v1.4.0
	github.com/trustelem/zxcvbn v1.0.1
	golang.org/x/crypto v0.49.0
	golang.org/x/net v0.52.0
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.41.0
	golang.org/x/text v0.35.0
	modernc.org/sqlite v1.48.1
)

require (
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/ultraviolet v0.0.0-20261008173134-6b8d4baf91b4 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/charmbracelet/x/termios v0.1.1 // indirect
	github.com/charmbracelet/x/windows v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/dlclark/regexp2 v1.12.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.1 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.30 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/test-go/testify v1.1.4 // indirect
	github.com/xo/terminfo v1.0.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	modernc.org/libc v1.70.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/makiuchi-d/gozxing => github.com/bashhack/gozxing v0.0.0-20260329180151-3b9d0c50fae9

replace charm.land/lipgloss/v2 => github.com/bashhack/lipgloss/v2 v2.0.7-0.20261013031702-ee18a8686e7f
