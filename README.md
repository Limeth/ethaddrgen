# ethaddrgen
[![Build Status](https://travis-ci.org/Limeth/ethaddrgen.svg?branch=master)](https://travis-ci.org/Limeth/ethaddrgen)
[![Build status](https://ci.appveyor.com/api/projects/status/tbnkiqgiqkrmtbcc?svg=true)](https://ci.appveyor.com/project/Limeth/ethaddrgen)
#### Custom Ethereum address generator
Get a shiny ethereum address and stand out from the crowd!

[![asciicast](https://asciinema.org/a/cmidn81zwi1c2n49ij4co9pg9.png)](https://asciinema.org/a/cmidn81zwi1c2n49ij4co9pg9)
Disclaimer: Do not use the private key shown in this demo; it's public, strangers could steal your Eth. Never share your private key with anyone. It's your and only your responsibility to keep your private key in secret.

## Features
- Regex support (`--regex`/`-e`): Use regex pattern matching
- Quiet mode (`--quiet`/`-q`): Output only the results
- Stream mode (`--stream`/`-s`): Keep outputting results
- Color settings (`--color`/`-c`): Enable/Disable colors
- Dictionary support: If no patterns are provided as arguments, patterns are read from the standard input

## Usage
Download the latest release [here](https://github.com/Limeth/ethaddrgen/releases).
To display usage, run `ethaddrgen -h` or `ethaddrgen --help` for a longer version.
`ethaddrgen` expects the last arguments to be patterns. If no patterns are provided as arguments, `ethaddrgen` reads patterns from the standard input where each pattern is on a separate line.

### Examples

#### Simple example
The following command will look for an address starting with either `c0ffee`, `deadbeef` or `c0c0a`.
If you are on Windows, use `ethaddrgen.exe` instead of `ethaddrgen`.
```sh
ethaddrgen c0ffee deadbeef c0c0a
```

#### Regex example
The following command will look for an address starting with 10 letters.
If you are on Windows, use `ethaddrgen.exe` instead of `ethaddrgen`.
```sh
ethaddrgen -e '^[abcdef]{10}'
```
Note that while supplying multiple regex patterns is supported, it is not recommended to use a large list of regex patterns.

#### Using pattern lists (dictionaries)
If no patterns are provided as arguments, patterns are read from the standard input. You can provide data to the standard input in various ways, depending on your platform:
* Windows:
```powershell
Get-Content patterns.txt | ethaddrgen.exe
```
* Unix (macOS/Linux):
```sh
cat patterns.txt | ethaddrgen
# or
ethaddrgen < patterns.txt
```
where the `patterns.txt` file is a newline-separated list of patterns, for example:
```
c0ffee
deadbeef
c0c0a
```
It is not recommended to use large pattern lists with regex, as combining these features significantly decreases performance.

## Compilation
The easiest way to get ethaddrgen is to download a pre-built binary [here](https://github.com/Limeth/ethaddrgen/releases).
You can also compile it yourself, if you wish so.
1. Install [Rust via Rustup.rs](http://rustup.rs/)
2. Clone this repository: `git clone https://github.com/Limeth/ethaddrgen.git; cd ethaddrgen`
3. Compile the project: `cargo build --release`. The binary can then be found at `target/release/ethaddrgen` or `./target/release/ethaddrgen.exe` on Windows machines.
