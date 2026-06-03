use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let cli = canopy_entitlements::Cli::parse();
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    ExitCode::from(canopy_entitlements::execute(cli, &mut stdout, &mut stderr))
}
