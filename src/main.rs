use clap::Parser;
use steg::cli::{CommandLineHandler, CommandLineInterface};
use steg::Result;

fn main() -> Result<()> {
    let command_line_interface = CommandLineInterface::parse();
    let mut cli_handler = CommandLineHandler::new();

    cli_handler.process_command(command_line_interface)?;

    Ok(())
}
