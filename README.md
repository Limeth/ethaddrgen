# ethaddrgen
#### Custom Ethereum address generator
Get a shiny ethereum address and stand out from the crowd!

## Compilation
1. Install [Rust via Rustup.rs](http://rustup.rs/)
2. Clone this repository: `git clone https://github.com/Limeth/ethaddrgen.git; cd ethaddrgen`
3. Compile the project: `cargo build --release`

## Usage
The binary can be found at `target/release/ethaddrgen` or `./target/release/ethaddrgen.exe` on Windows machines.
To run it, provide a single argument -- the **regex** the resulting address should match to.

For example:
* `target/release/ethaddrgen feed` will generate an address which contains the word `feed`,
* `target/release/ethaddrgen ^beef` will generate an address starting with `beef`
