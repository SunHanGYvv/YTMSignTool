mod cli;
mod crypto;
mod prepare;
mod image;
mod keys;
mod secure_image;
mod types;

use clap::Parser;

use crate::cli::{
    cmd_convert, cmd_info, cmd_keygen, cmd_prepare, cmd_sign, cmd_verify, Cli, Commands,
};

fn init_logging(slient: bool) {
    use std::io::Write;

    let mut builder = env_logger::Builder::new();
    if slient {
        builder.filter_level(log::LevelFilter::Off);
    } else {
        builder.parse_env(env_logger::Env::default().default_filter_or("info"));
    }
    builder
        .format_timestamp(None)
        .format_module_path(false)
        .format_target(false)
        .format(|buf, record| writeln!(buf, "{}", record.args()));
    let _ = builder.try_init();
}

fn main() {
    let cli = Cli::parse();
    init_logging(cli.slient);

    if let Err(e) = run(cli) {
        log::error!("{:#}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Sign {
            input,
            keys,
            output,
            format,
            base,
            size,
            boot,
        } => {
            cmd_sign(
                &input,
                &keys,
                output.as_deref(),
                format.as_deref(),
                base.as_deref(),
                size.as_deref(),
                boot.as_deref(),
            )?;
        }
        Commands::Verify { input, keys, base } => {
            cmd_verify(&input, keys.as_deref(), base.as_deref())?;
        }
        Commands::Keygen { input, base, output } => {
            cmd_keygen(input.as_deref(), base.as_deref(), output.as_deref())?;
        }
        Commands::Prepare {
            keys,
            output,
            format,
            template,
        } => {
            cmd_prepare(
                &keys,
                output.as_deref(),
                format.as_deref(),
                template.as_deref(),
            )?;
        }
        Commands::Info { input, keys, base } => {
            cmd_info(&input, keys.as_deref(), base.as_deref())?;
        }
        Commands::Convert {
            input,
            output,
            format,
            base,
        } => {
            cmd_convert(
                &input,
                output.as_deref(),
                format.as_deref(),
                base.as_deref(),
            )?;
        }
    }

    Ok(())
}
