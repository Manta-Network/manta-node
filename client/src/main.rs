use pallet_manta_dap::crypto_types::*;
use pallet_manta_dap::priv_coin::*;
use structopt::StructOpt;

/// Search for a pattern in a file and display the lines that contain it.
#[derive(StructOpt)]
struct Cli {
    /// The pattern to look for
    pattern: String,
    /// The path to the file to read
    #[structopt(parse(from_os_str))]
    path: std::path::PathBuf,
}


fn main() {
   let args = Cli::from_args();

    
    println!("Hello, world!");
}
