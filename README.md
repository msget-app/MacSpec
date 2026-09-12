# MacSpec

Export your Mac’s hardware identifiers and macOS version as a Base64 configuration
for MSGET.

## Run

Requires macOS 11+ and Apple’s Command Line Tools, which include Swift and the
macOS SDK. Full Xcode and Homebrew are unnecessary.

If the tools are missing, run the following built-in macOS command and complete
the installation dialog:

```sh
xcode-select --install
```

Run in Bash, Zsh, or Fish without cloning:

```sh
curl -fsSL https://raw.githubusercontent.com/msget-app/MacSpec/main/MacSpec.swift | xcrun swift -
```

Copy the single output line into MSGET’s hardware configuration input. Keep it
private: it contains device identifiers.

For diagnostics, replace `xcrun swift -` with `env HWINFO_DEBUG=1 xcrun swift -`.
Errors go to stderr.
