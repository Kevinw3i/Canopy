use std::io::{self, Write};
use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;

pub mod catalog;

#[derive(Debug, Parser)]
#[command(
    name = "canopy-entitlements",
    about = "Canopy entitlement catalog tooling",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a low-level runtime entitlement file from a catalog.
    Generate(GenerateArgs),
    /// Validate catalog input and the generated runtime entitlement file.
    Validate(ValidateArgs),
    /// Preview one Canopy group's effective access.
    Preview(PreviewArgs),
    /// Compare semantic access changes between two catalogs.
    Diff(DiffArgs),
    /// Explain resolved access for one login identity.
    Explain(ExplainArgs),
    /// Statically simulate one scoped operation.
    DryRun(DryRunArgs),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[derive(Clone, Debug, Args)]
pub struct OutputArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// High-level catalog source file.
    #[arg(long, value_name = "PATH")]
    pub catalog: PathBuf,

    /// Low-level runtime entitlement file to write.
    #[arg(long = "output", value_name = "PATH")]
    pub output_file: PathBuf,

    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Debug, Args)]
pub struct ValidateArgs {
    /// High-level catalog source file.
    #[arg(long, value_name = "PATH")]
    pub catalog: PathBuf,

    /// Generated low-level runtime entitlement file to validate.
    #[arg(long, value_name = "PATH")]
    pub runtime_file: PathBuf,

    /// Terraform tfvars file used for deploy-time IAM consistency checks.
    #[arg(long, value_name = "PATH")]
    pub tfvars: PathBuf,

    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Debug, Args)]
pub struct PreviewArgs {
    /// High-level catalog source file.
    #[arg(long, value_name = "PATH")]
    pub catalog: PathBuf,

    /// Canopy group to preview.
    #[arg(long)]
    pub group: String,

    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Baseline catalog file.
    #[arg(long, value_name = "PATH")]
    pub old: PathBuf,

    /// Candidate catalog file.
    #[arg(long, value_name = "PATH")]
    pub new: PathBuf,

    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Debug, Args)]
pub struct ExplainArgs {
    /// High-level catalog source file.
    #[arg(long, value_name = "PATH")]
    pub catalog: PathBuf,

    /// OIDC subject.
    #[arg(long)]
    pub sub: String,

    /// OIDC email claim.
    #[arg(long)]
    pub email: Option<String>,

    /// Whether the OIDC email claim is verified, enabling email fallback memberships.
    #[arg(long, default_value_t = false)]
    pub email_verified: bool,

    /// External Cognito group from the OIDC group claim. Repeat for multiple groups.
    #[arg(long = "external-group", action = ArgAction::Append)]
    pub external_groups: Vec<String>,

    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Debug, Args)]
pub struct DryRunArgs {
    /// High-level catalog source file.
    #[arg(long, value_name = "PATH")]
    pub catalog: PathBuf,

    /// Operation to simulate, such as ecs-exec or ec2-power.
    #[arg(long)]
    pub operation: String,

    /// OIDC subject.
    #[arg(long)]
    pub sub: String,

    /// OIDC email claim.
    #[arg(long)]
    pub email: Option<String>,

    /// Whether the OIDC email claim is verified, enabling email fallback memberships.
    #[arg(long, default_value_t = false)]
    pub email_verified: bool,

    /// External Cognito group from the OIDC group claim. Repeat for multiple groups.
    #[arg(long = "external-group", action = ArgAction::Append)]
    pub external_groups: Vec<String>,

    /// AWS account id for scoped operations.
    #[arg(long)]
    pub account: Option<String>,

    /// AWS region for scoped operations.
    #[arg(long)]
    pub region: Option<String>,

    /// ECS cluster name or ARN.
    #[arg(long)]
    pub cluster: Option<String>,

    /// CloudWatch log group ARN for CloudWatch dry-runs.
    #[arg(long)]
    pub log_group_arn: Option<String>,

    /// OS user for SSM shell dry-runs.
    #[arg(long)]
    pub os_user: Option<String>,

    /// EC2 instance tag input. Repeat KEY=VALUE for multiple tags.
    #[arg(long = "instance-tags", value_name = "KEY=VALUE", action = ArgAction::Append)]
    pub instance_tags: Vec<String>,

    /// ECS task tag selector input. Repeat KEY=VALUE for multiple tags.
    #[arg(long = "task-tags", value_name = "KEY=VALUE", action = ArgAction::Append)]
    pub task_tags: Vec<String>,

    /// Container name for ECS exec dry-runs.
    #[arg(long)]
    pub container: Option<String>,

    /// Database scope name for MCP database dry-runs.
    #[arg(long)]
    pub scope: Option<String>,

    /// Database connection name for MCP database dry-runs.
    #[arg(long)]
    pub connection: Option<String>,

    /// Database environment for MCP database dry-runs.
    #[arg(long)]
    pub environment: Option<String>,

    /// Database schema for MCP database dry-runs.
    #[arg(long)]
    pub schema: Option<String>,

    /// Database table for MCP database dry-runs.
    #[arg(long)]
    pub table: Option<String>,

    /// Database action for MCP database dry-runs.
    #[arg(long)]
    pub action: Option<String>,

    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Debug, Serialize)]
pub struct CommandStatus {
    pub status: &'static str,
    pub command: &'static str,
    pub message: String,
}

pub trait HumanOutput {
    fn write_human<W: Write>(&self, writer: &mut W) -> io::Result<()>;
}

impl HumanOutput for CommandStatus {
    fn write_human<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writeln!(writer, "{}: {}", self.status, self.message)
    }
}

impl HumanOutput for catalog::GenerateStatus {
    fn write_human<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writeln!(
            writer,
            "generated {} rule(s), {} group mapping(s), and {} membership(s) to {}",
            self.rules, self.group_mappings, self.memberships, self.output
        )
    }
}

impl HumanOutput for catalog::ValidateStatus {
    fn write_human<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writeln!(
            writer,
            "validated catalog {}, runtime {}, and deployment tfvars {}",
            self.catalog, self.runtime_file, self.tfvars
        )
    }
}

impl HumanOutput for catalog::PreviewOutput {
    fn write_human<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writeln!(
            writer,
            "group {} has {} package(s)",
            self.group,
            self.packages.len()
        )?;
        for package in &self.packages {
            writeln!(
                writer,
                "- {}: {} feature(s), {} account role(s)",
                package.package,
                package.features.len(),
                package.accounts.len()
            )?;
        }
        Ok(())
    }
}

impl HumanOutput for catalog::DiffOutput {
    fn write_human<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writeln!(
            writer,
            "diff added {} grant(s), removed {} grant(s), high-risk added {} grant(s)",
            self.added.len(),
            self.removed.len(),
            self.high_risk_changes.len()
        )
    }
}

impl HumanOutput for catalog::ExplainOutput {
    fn write_human<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writeln!(
            writer,
            "resolved {} group(s) and {} matched package(s) for {}",
            self.resolved_groups.len(),
            self.matched_packages.len(),
            self.sub
        )
    }
}

impl HumanOutput for catalog::DryRunOutput {
    fn write_human<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writeln!(
            writer,
            "{}: {} ({})",
            self.operation,
            if self.allow { "allow" } else { "deny" },
            self.reason
        )
    }
}

pub fn write_output<T, W>(format: OutputFormat, writer: &mut W, value: &T) -> anyhow::Result<()>
where
    T: HumanOutput + Serialize,
    W: Write,
{
    match format {
        OutputFormat::Human => value.write_human(writer)?,
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut *writer, value)?;
            writeln!(writer)?;
        }
    }
    Ok(())
}

pub fn execute<W, E>(cli: Cli, stdout: &mut W, stderr: &mut E) -> u8
where
    W: Write,
    E: Write,
{
    match cli.command {
        Command::Generate(args) => {
            let format = args.output.format;
            match catalog::generate_runtime_file(&args.catalog, &args.output_file) {
                Ok(status) => match write_output(format, stdout, &status) {
                    Ok(()) => 0,
                    Err(err) => {
                        let _ = writeln!(stderr, "failed to write output: {err}");
                        1
                    }
                },
                Err(err) => {
                    let status = CommandStatus {
                        status: "error",
                        command: "generate",
                        message: format!("{err:#}"),
                    };
                    let _ = write_output(format, stderr, &status);
                    1
                }
            }
        }
        Command::Validate(args) => {
            let format = args.output.format;
            match catalog::validate_catalog_files(&args.catalog, &args.runtime_file, &args.tfvars) {
                Ok(status) => match write_output(format, stdout, &status) {
                    Ok(()) => 0,
                    Err(err) => {
                        let _ = writeln!(stderr, "failed to write output: {err}");
                        1
                    }
                },
                Err(err) => {
                    let status = CommandStatus {
                        status: "error",
                        command: "validate",
                        message: format!("{err:#}"),
                    };
                    let _ = write_output(format, stderr, &status);
                    1
                }
            }
        }
        Command::Preview(args) => {
            let format = args.output.format;
            match catalog::preview_catalog_file(&args.catalog, &args.group) {
                Ok(output) => match write_output(format, stdout, &output) {
                    Ok(()) => 0,
                    Err(err) => {
                        let _ = writeln!(stderr, "failed to write output: {err}");
                        1
                    }
                },
                Err(err) => {
                    let status = CommandStatus {
                        status: "error",
                        command: "preview",
                        message: format!("{err:#}"),
                    };
                    let _ = write_output(format, stderr, &status);
                    1
                }
            }
        }
        Command::Diff(args) => {
            let format = args.output.format;
            match catalog::diff_catalog_files(&args.old, &args.new) {
                Ok(output) => match write_output(format, stdout, &output) {
                    Ok(()) => 0,
                    Err(err) => {
                        let _ = writeln!(stderr, "failed to write output: {err}");
                        1
                    }
                },
                Err(err) => {
                    let status = CommandStatus {
                        status: "error",
                        command: "diff",
                        message: format!("{err:#}"),
                    };
                    let _ = write_output(format, stderr, &status);
                    1
                }
            }
        }
        Command::Explain(args) => {
            let format = args.output.format;
            let request = catalog::ExplainRequest {
                sub: args.sub,
                email: args.email,
                email_verified: args.email_verified,
                external_groups: args.external_groups,
            };
            match catalog::explain_catalog_file(&args.catalog, request) {
                Ok(output) => match write_output(format, stdout, &output) {
                    Ok(()) => 0,
                    Err(err) => {
                        let _ = writeln!(stderr, "failed to write output: {err}");
                        1
                    }
                },
                Err(err) => {
                    let status = CommandStatus {
                        status: "error",
                        command: "explain",
                        message: format!("{err:#}"),
                    };
                    let _ = write_output(format, stderr, &status);
                    1
                }
            }
        }
        Command::DryRun(args) => {
            let format = args.output.format;
            let request = catalog::DryRunRequest {
                operation: args.operation,
                sub: args.sub,
                email: args.email,
                email_verified: args.email_verified,
                external_groups: args.external_groups,
                account: args.account,
                region: args.region,
                cluster: args.cluster,
                log_group_arn: args.log_group_arn,
                os_user: args.os_user,
                instance_tags: args.instance_tags,
                task_tags: args.task_tags,
                container: args.container,
                scope: args.scope,
                connection: args.connection,
                environment: args.environment,
                schema: args.schema,
                table: args.table,
                action: args.action,
            };
            match catalog::dry_run_catalog_file(&args.catalog, request) {
                Ok(output) => match write_output(format, stdout, &output) {
                    Ok(()) => 0,
                    Err(err) => {
                        let _ = writeln!(stderr, "failed to write output: {err}");
                        1
                    }
                },
                Err(err) => {
                    let status = CommandStatus {
                        status: "error",
                        command: "dry-run",
                        message: format!("{err:#}"),
                    };
                    let _ = write_output(format, stderr, &status);
                    1
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_generate_command_shape() {
        let cli = Cli::try_parse_from([
            "canopy-entitlements",
            "generate",
            "--catalog",
            "entitlements.catalog.toml",
            "--output",
            "entitlements.generated.toml",
            "--format",
            "json",
        ])
        .unwrap();

        let Command::Generate(args) = cli.command else {
            panic!("expected generate command");
        };
        assert_eq!(args.catalog, PathBuf::from("entitlements.catalog.toml"));
        assert_eq!(
            args.output_file,
            PathBuf::from("entitlements.generated.toml")
        );
        assert_eq!(args.output.format, OutputFormat::Json);
    }

    #[test]
    fn parses_explain_external_groups_as_repeated_flags() {
        let cli = Cli::try_parse_from([
            "canopy-entitlements",
            "explain",
            "--catalog",
            "entitlements.catalog.toml",
            "--sub",
            "user-sub",
            "--email",
            "alice@example.com",
            "--external-group",
            "canopy-platform-engineering",
            "--external-group",
            "canopy-readonly-ops",
        ])
        .unwrap();

        let Command::Explain(args) = cli.command else {
            panic!("expected explain command");
        };
        assert_eq!(
            args.external_groups,
            vec!["canopy-platform-engineering", "canopy-readonly-ops"]
        );
    }

    #[test]
    fn json_output_helper_renders_machine_readable_status() {
        let status = CommandStatus {
            status: "ok",
            command: "generate",
            message: "generated".into(),
        };
        let mut output = Vec::new();

        write_output(OutputFormat::Json, &mut output, &status).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["command"], "generate");
    }
}
