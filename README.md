# ethaddrgen
[![Build Status](https://travis-ci.org/Limeth/ethaddrgen.svg?branch=master)](https://travis-ci.org/Limeth/ethaddrgen)
[![Build status](https://ci.appveyor.com/api/projects/status/tbnkiqgiqkrmtbcc?svg=true)](https://ci.appveyor.com/project/Limeth/ethaddrgen)
#### Custom Ethereum address generator
Get a shiny ethereum address and stand out from the crowd!

[![asciicast](https://asciinema.org/a/cmidn81zwi1c2n49ij4co9pg9.png)](https://asciinema.org/a/cmidn81zwi1c2n49ij4co9pg9)

## Features
- Regex support (`--regex`/`-e`): Use regex pattern matching
- Quiet mode (`--quiet`/`-q`): Output only the results
- Stream mode (`--stream`/`-s`): Keep outputting results
- Color settings (`--color`/`-c`): Enable/Disable colors

## Usage
Download the latest release [here](https://github.com/Limeth/ethaddrgen/releases).
To display usage, run `ethaddrgen -h` or `ethaddrgen --help` for a longer version.
`ethaddrgen` expects the last arguments to be patterns. If no patterns are provided as arguments, `ethaddrgen` reads patterns from the standard input where each pattern is on a separate line.

## Compilation
The easiest way to get ethaddrgen is to download a pre-built binary [here](https://github.com/Limeth/ethaddrgen/releases).
You can also compile it yourself, if you wish so.
1. Install [Rust via Rustup.rs](http://rustup.rs/)
2. Clone this repository: `git clone https://github.com/Limeth/ethaddrgen.git; cd ethaddrgen`
3. Compile the project: `cargo build --release`. The binary can then be found at `target/release/ethaddrgen` or `./target/release/ethaddrgen.exe` on Windows machines.
