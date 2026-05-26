use shared::dto::pty_spawn::PtySpawnSpec;
use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;
use std::process::Command;

const AWS_CLI_MAC_PKG_URL: &str = "https://awscli.amazonaws.com/AWSCLIV2.pkg";
const AWS_CLI_LINUX_X86_64_ZIP_URL: &str =
    "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip";
const AWS_CLI_LINUX_AARCH64_ZIP_URL: &str =
    "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip";
const SSM_PLUGIN_MAC_X86_64_PKG_URL: &str =
    "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/mac/session-manager-plugin.pkg";
const SSM_PLUGIN_MAC_ARM64_PKG_URL: &str =
    "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/mac_arm64/session-manager-plugin.pkg";
// AWS macOS installers are expected to be signed by AMZN Mobile LLC.
// If AWS rotates signing identity, update this value from AWS/Apple
// official installer-signature guidance before shipping auto-install.
const AWS_DEVELOPER_ID_INSTALLER_TEAM_ID: &str = "94KV3E626L";

// AWS CLI PGP key from the official AWS CLI v2 install guide:
// https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
// Key fingerprint: FB5D B77F D5C1 18B8 0511 ADA8 A631 0ACC 4672 475C
// Key ID: A6310ACC4672475C. Current AWS-published expiry: 2026-07-07.
// If verification starts failing because AWS rotates or expires the signing
// key, update this block from the same doc.
const AWS_CLI_PGP_FINGERPRINT: &str = "FB5DB77FD5C118B80511ADA8A6310ACC4672475C";
const AWS_CLI_PGP_PUBLIC_KEY: &str = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----
mQINBF2Cr7UBEADJZHcgusOJl7ENSyumXh85z0TRV0xJorM2B/JL0kHOyigQluUG
ZMLhENaG0bYatdrKP+3H91lvK050pXwnO/R7fB/FSTouki4ciIx5OuLlnJZIxSzx
PqGl0mkxImLNbGWoi6Lto0LYxqHN2iQtzlwTVmq9733zd3XfcXrZ3+LblHAgEt5G
TfNxEKJ8soPLyWmwDH6HWCnjZ/aIQRBTIQ05uVeEoYxSh6wOai7ss/KveoSNBbYz
gbdzoqI2Y8cgH2nbfgp3DSasaLZEdCSsIsK1u05CinE7k2qZ7KgKAUIcT/cR/grk
C6VwsnDU0OUCideXcQ8WeHutqvgZH1JgKDbznoIzeQHJD238GEu+eKhRHcz8/jeG
94zkcgJOz3KbZGYMiTh277Fvj9zzvZsbMBCedV1BTg3TqgvdX4bdkhf5cH+7NtWO
lrFj6UwAsGukBTAOxC0l/dnSmZhJ7Z1KmEWilro/gOrjtOxqRQutlIqG22TaqoPG
fYVN+en3Zwbt97kcgZDwqbuykNt64oZWc4XKCa3mprEGC3IbJTBFqglXmZ7l9ywG
EEUJYOlb2XrSuPWml39beWdKM8kzr1OjnlOm6+lpTRCBfo0wa9F8YZRhHPAkwKkX
XDeOGpWRj4ohOx0d2GWkyV5xyN14p2tQOCdOODmz80yUTgRpPVQUtOEhXQARAQAB
tCFBV1MgQ0xJIFRlYW0gPGF3cy1jbGlAYW1hem9uLmNvbT6JAlQEEwEIAD4CGwMF
CwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQT7Xbd/1cEYuAURraimMQrMRnJHXAUC
aGveYQUJDMpiLAAKCRCmMQrMRnJHXKBYD/9Ab0qQdGiO5hObchG8xh8Rpb4Mjyf6
0JrVo6m8GNjNj6BHkSc8fuTQJ/FaEhaQxj3pjZ3GXPrXjIIVChmICLlFuRXYzrXc
Pw0lniybypsZEVai5kO0tCNBCCFuMN9RsmmRG8mf7lC4FSTbUDmxG/QlYK+0IV/l
uJkzxWa+rySkdpm0JdqumjegNRgObdXHAQDWlubWQHWyZyIQ2B4U7AxqSpcdJp6I
S4Zds4wVLd1WE5pquYQ8vS2cNlDm4QNg8wTj58e3lKN47hXHMIb6CHxRnb947oJa
pg189LLPR5koh+EorNkA1wu5mAJtJvy5YMsppy2y/kIjp3lyY6AmPT1posgGk70Z
CmToEZ5rbd7ARExtlh76A0cabMDFlEHDIK8RNUOSRr7L64+KxOUegKBfQHb9dADY
qqiKqpCbKgvtWlds909Ms74JBgr2KwZCSY1HaOxnIr4CY43QRqAq5YHOay/mU+6w
hhmdF18vpyK0vfkvvGresWtSXbag7Hkt3XjaEw76BzxQH21EBDqU8WJVjHgU6ru+
DJTs+SxgJbaT3hb/vyjlw0lK+hFfhWKRwgOXH8vqducF95NRSUxtS4fpqxWVaw3Q
V2OWSjbne99A5EPEySzryFTKbMGwaTlAwMCwYevt4YT6eb7NmFhTx0Fis4TalUs+
j+c7Kg92pDx2uQ==
=OBAt
-----END PGP PUBLIC KEY BLOCK-----"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LocalDependency {
    AwsCliV2,
    Ssh,
    SessionManagerPlugin,
}

impl LocalDependency {
    pub fn label(self) -> &'static str {
        match self {
            Self::AwsCliV2 => "AWS CLI v2",
            Self::Ssh => "OpenSSH client",
            Self::SessionManagerPlugin => "Session Manager Plugin",
        }
    }

    pub fn install_prompt(self) -> &'static str {
        match self {
            Self::AwsCliV2 => {
                "Install AWS CLI v2 now? This downloads the official AWS installer and may ask for sudo."
            }
            Self::SessionManagerPlugin => {
                "Install Session Manager Plugin now? This downloads the official AWS installer and may ask for sudo."
            }
            Self::Ssh => "Install OpenSSH client now?",
        }
    }

    pub fn manual_install_url(self) -> &'static str {
        match self {
            Self::AwsCliV2 => "https://aws.amazon.com/cli/",
            Self::Ssh => "https://www.openssh.com/",
            Self::SessionManagerPlugin => {
                "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html"
            }
        }
    }

    pub fn can_auto_install(self) -> bool {
        matches!(self, Self::AwsCliV2 | Self::SessionManagerPlugin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyIssue {
    pub dependency: LocalDependency,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status_success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub trait CommandRunner {
    fn output(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput>;
    fn status(&self, program: &str, args: &[String]) -> io::Result<bool>;
}

#[derive(Debug, Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn output(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        let output = Command::new(program).args(args).output()?;
        Ok(CommandOutput {
            status_success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn status(&self, program: &str, args: &[String]) -> io::Result<bool> {
        Ok(Command::new(program).args(args).status()?.success())
    }
}

pub fn is_aws_cli_v2_version(version_output: &str) -> bool {
    let Some(rest) = version_output.trim_start().strip_prefix("aws-cli/2.") else {
        return false;
    };
    rest.chars().next().is_some_and(|ch| ch.is_ascii_digit())
}

pub fn required_dependencies_for_connect(resp: &PtySpawnSpec) -> Vec<LocalDependency> {
    let mut deps = BTreeSet::new();

    match normalized_command_name(&resp.command).as_deref() {
        Some("aws") => {
            deps.insert(LocalDependency::AwsCliV2);
            if args_start_with(&resp.args, &["ec2-instance-connect", "ssh"]) {
                deps.insert(LocalDependency::Ssh);
            }
            if args_start_with(&resp.args, &["ssm", "start-session"]) {
                deps.insert(LocalDependency::SessionManagerPlugin);
            }
            if args_start_with(&resp.args, &["ecs", "execute-command"]) {
                deps.insert(LocalDependency::SessionManagerPlugin);
            }
        }
        Some("ssh") => {
            deps.insert(LocalDependency::Ssh);
            if resp.args.iter().any(|arg| contains_ssm_proxy_command(arg)) {
                deps.insert(LocalDependency::AwsCliV2);
                deps.insert(LocalDependency::SessionManagerPlugin);
            }
        }
        _ => {}
    }

    deps.into_iter().collect()
}

pub fn check_required_dependencies<R: CommandRunner>(
    deps: &[LocalDependency],
    runner: &R,
) -> Vec<DependencyIssue> {
    deps.iter()
        .filter_map(|dep| check_dependency(*dep, runner))
        .collect()
}

pub fn install_dependency<R: CommandRunner>(
    dependency: LocalDependency,
    runner: &R,
) -> Result<(), String> {
    match dependency {
        LocalDependency::AwsCliV2 => install_aws_cli_v2(runner),
        LocalDependency::SessionManagerPlugin => install_session_manager_plugin(runner),
        LocalDependency::Ssh => Err(format!(
            "{} cannot be installed automatically. Install it manually: {}",
            dependency.label(),
            dependency.manual_install_url()
        )),
    }
}

pub fn format_dependency_issues(issues: &[DependencyIssue]) -> String {
    issues
        .iter()
        .map(|issue| {
            format!(
                "{}: {}. Manual install: {}",
                issue.dependency.label(),
                issue.reason,
                issue.dependency.manual_install_url()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn args_start_with(args: &[String], prefix: &[&str]) -> bool {
    args.len() >= prefix.len()
        && args
            .iter()
            .zip(prefix.iter())
            .all(|(actual, expected)| actual == expected)
}

fn normalized_command_name(command: &str) -> Option<String> {
    let file_name = std::path::Path::new(command).file_name()?;
    let name = file_name.to_string_lossy();
    Some(name.trim_end_matches(".exe").to_ascii_lowercase())
}

fn contains_ssm_proxy_command(arg: &str) -> bool {
    if !arg.to_ascii_lowercase().contains("proxycommand") {
        return false;
    }
    let normalized = arg
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    normalized.contains("proxycommand=aws ssm start-session")
        || normalized.contains("proxycommand = aws ssm start-session")
}

fn check_dependency<R: CommandRunner>(
    dependency: LocalDependency,
    runner: &R,
) -> Option<DependencyIssue> {
    match dependency {
        LocalDependency::AwsCliV2 => check_aws_cli_v2(runner),
        LocalDependency::Ssh => check_executable(dependency, "ssh", &["-V"], runner),
        LocalDependency::SessionManagerPlugin => {
            check_executable(dependency, "session-manager-plugin", &["--version"], runner)
        }
    }
}

fn check_aws_cli_v2<R: CommandRunner>(runner: &R) -> Option<DependencyIssue> {
    match runner.output("aws", &["--version"]) {
        Ok(output) => {
            let version = combined_output(&output);
            if is_aws_cli_v2_version(&version) {
                None
            } else if version.trim().is_empty() {
                Some(issue(
                    LocalDependency::AwsCliV2,
                    "aws --version did not return a version",
                ))
            } else {
                Some(issue(
                    LocalDependency::AwsCliV2,
                    format!("AWS CLI v2 is required, found {}", version.trim()),
                ))
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            Some(issue(LocalDependency::AwsCliV2, "aws command not found"))
        }
        Err(e) => Some(issue(
            LocalDependency::AwsCliV2,
            format!("failed to run aws --version: {e}"),
        )),
    }
}

fn check_executable<R: CommandRunner>(
    dependency: LocalDependency,
    program: &str,
    args: &[&str],
    runner: &R,
) -> Option<DependencyIssue> {
    match runner.output(program, args) {
        Ok(_) => None,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            Some(issue(dependency, format!("{program} command not found")))
        }
        Err(e) => Some(issue(dependency, format!("failed to run {program}: {e}"))),
    }
}

fn issue(dependency: LocalDependency, reason: impl Into<String>) -> DependencyIssue {
    DependencyIssue {
        dependency,
        reason: reason.into(),
    }
}

fn combined_output(output: &CommandOutput) -> String {
    let mut combined = String::new();
    combined.push_str(output.stdout.trim());
    if !output.stderr.trim().is_empty() {
        if !combined.is_empty() {
            combined.push(' ');
        }
        combined.push_str(output.stderr.trim());
    }
    combined
}

struct TempWorkspace {
    path: PathBuf,
}

impl TempWorkspace {
    fn new(prefix: &str) -> Result<Self, String> {
        for _ in 0..10 {
            let path = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    if let Err(e) = set_private_dir_permissions(&path) {
                        let _ = std::fs::remove_dir_all(&path);
                        return Err(format!("Failed to secure temporary directory: {e}"));
                    }
                    return Ok(Self { path });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("Failed to create temporary directory: {e}")),
            }
        }

        Err("Failed to create a unique temporary directory".into())
    }

    fn join(&self, file_name: &str) -> PathBuf {
        self.path.join(file_name)
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &std::path::Path) -> io::Result<()> {
    Ok(())
}

fn install_aws_cli_v2<R: CommandRunner>(runner: &R) -> Result<(), String> {
    let workspace = TempWorkspace::new("canopy-awscli")?;

    match std::env::consts::OS {
        "macos" => {
            let pkg = workspace.join("AWSCLIV2.pkg");
            download_file(
                runner,
                AWS_CLI_MAC_PKG_URL,
                &pkg,
                "Downloading AWS CLI v2 installer",
            )?;
            verify_macos_pkg_signature(runner, &pkg, "AWS CLI v2 installer")?;
            run_step(
                runner,
                "sudo",
                vec![
                    "installer".to_string(),
                    "-pkg".to_string(),
                    pkg.display().to_string(),
                    "-target".to_string(),
                    "/".to_string(),
                ],
                "Running AWS CLI v2 installer",
            )
        }
        "linux" => {
            let zip = workspace.join("awscliv2.zip");
            let sig = workspace.join("awscliv2.sig");
            let install_dir = workspace.join("awscliv2-install");
            let url = aws_cli_linux_zip_url_for_arch(std::env::consts::ARCH)?;
            download_file(runner, url, &zip, "Downloading AWS CLI v2 installer")?;
            download_file(
                runner,
                &format!("{url}.sig"),
                &sig,
                "Downloading AWS CLI v2 installer signature",
            )?;
            verify_aws_cli_zip_signature(runner, &workspace, &zip, &sig)?;
            run_step(
                runner,
                "unzip",
                vec![
                    "-q".to_string(),
                    "-o".to_string(),
                    zip.display().to_string(),
                    "-d".to_string(),
                    install_dir.display().to_string(),
                ],
                "Extracting AWS CLI v2 installer",
            )?;
            let installer = install_dir.join("aws").join("install");
            run_step(
                runner,
                "sudo",
                vec![installer.display().to_string(), "--update".to_string()],
                "Running AWS CLI v2 installer",
            )
        }
        other => Err(format!(
            "Automatic AWS CLI v2 install is not supported on {other}. Install manually: {}",
            LocalDependency::AwsCliV2.manual_install_url()
        )),
    }
}

fn install_session_manager_plugin<R: CommandRunner>(runner: &R) -> Result<(), String> {
    let workspace = TempWorkspace::new("canopy-ssm-plugin")?;

    match std::env::consts::OS {
        "macos" => {
            let pkg = workspace.join("session-manager-plugin.pkg");
            let url = ssm_plugin_mac_pkg_url_for_arch(std::env::consts::ARCH);
            download_file(
                runner,
                url,
                &pkg,
                "Downloading Session Manager Plugin installer",
            )?;
            verify_macos_pkg_signature(runner, &pkg, "Session Manager Plugin installer")?;
            run_step(
                runner,
                "sudo",
                vec![
                    "installer".to_string(),
                    "-pkg".to_string(),
                    pkg.display().to_string(),
                    "-target".to_string(),
                    "/".to_string(),
                ],
                "Running Session Manager Plugin installer",
            )
        }
        "linux" => install_session_manager_plugin_linux(),
        other => Err(format!(
            "Automatic Session Manager Plugin install is not supported on {other}. Install manually: {}",
            LocalDependency::SessionManagerPlugin.manual_install_url()
        )),
    }
}

fn install_session_manager_plugin_linux() -> Result<(), String> {
    Err(format!(
        "Automatic Linux install for Session Manager Plugin is disabled because no verified installer signature is configured. Install manually: {}",
        LocalDependency::SessionManagerPlugin.manual_install_url()
    ))
}

fn download_file<R: CommandRunner>(
    runner: &R,
    url: &str,
    dest: &std::path::Path,
    label: &str,
) -> Result<(), String> {
    run_step(
        runner,
        "curl",
        vec![
            "--proto".to_string(),
            "=https".to_string(),
            "--tlsv1.2".to_string(),
            "-fsSL".to_string(),
            url.to_string(),
            "-o".to_string(),
            dest.display().to_string(),
        ],
        label,
    )
}

fn verify_macos_pkg_signature<R: CommandRunner>(
    runner: &R,
    pkg: &std::path::Path,
    label: &str,
) -> Result<(), String> {
    let pkg_path = pkg.display().to_string();
    let output = runner
        .output("pkgutil", &["--check-signature", &pkg_path])
        .map_err(|e| format!("Failed to verify {label} signature: {e}"))?;
    let combined = combined_output(&output);
    if !output.status_success {
        return Err(format!("{label} signature verification failed: {combined}"));
    }
    if !macos_pkg_signature_is_amazon(&combined) {
        return Err(format!(
            "{label} is not signed by expected AWS Developer ID team {AWS_DEVELOPER_ID_INSTALLER_TEAM_ID}: {combined}"
        ));
    }
    Ok(())
}

fn macos_pkg_signature_is_amazon(signature_output: &str) -> bool {
    signature_output.contains("Developer ID Installer")
        && signature_output.contains(AWS_DEVELOPER_ID_INSTALLER_TEAM_ID)
}

fn verify_aws_cli_zip_signature<R: CommandRunner>(
    runner: &R,
    workspace: &TempWorkspace,
    zip: &std::path::Path,
    sig: &std::path::Path,
) -> Result<(), String> {
    ensure_gpg_available(runner)?;

    let key_file = workspace.join("aws-cli-public-key.asc");
    let gpg_home = workspace.join("gnupg");
    std::fs::write(&key_file, AWS_CLI_PGP_PUBLIC_KEY)
        .map_err(|e| format!("Failed to write AWS CLI public key: {e}"))?;
    std::fs::create_dir(&gpg_home).map_err(|e| format!("Failed to create GPG home: {e}"))?;
    set_private_dir_permissions(&gpg_home)
        .map_err(|e| format!("Failed to secure GPG home: {e}"))?;

    run_step(
        runner,
        "gpg",
        vec![
            "--homedir".to_string(),
            gpg_home.display().to_string(),
            "--batch".to_string(),
            "--import".to_string(),
            key_file.display().to_string(),
        ],
        "Importing AWS CLI PGP key",
    )?;
    verify_gpg_signature(runner, &gpg_home, zip, sig, "AWS CLI v2 installer")
}

fn ensure_gpg_available<R: CommandRunner>(runner: &R) -> Result<(), String> {
    let output = runner.output("gpg", &["--version"]).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            "Required command 'gpg' not found. Install GnuPG to verify AWS CLI installer signatures, or install AWS CLI manually from https://aws.amazon.com/cli/".to_string()
        } else {
            format!("Failed to run gpg: {e}")
        }
    })?;
    if output.status_success {
        Ok(())
    } else {
        Err(format!(
            "Required command 'gpg' failed: {}",
            combined_output(&output)
        ))
    }
}

fn verify_gpg_signature<R: CommandRunner>(
    runner: &R,
    gpg_home: &std::path::Path,
    artifact: &std::path::Path,
    signature: &std::path::Path,
    label: &str,
) -> Result<(), String> {
    let gpg_home = gpg_home.display().to_string();
    let sig_path = signature.display().to_string();
    let artifact_path = artifact.display().to_string();
    let output = runner
        .output(
            "gpg",
            &[
                "--homedir",
                &gpg_home,
                "--batch",
                "--status-fd",
                "1",
                "--verify",
                &sig_path,
                &artifact_path,
            ],
        )
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                "Required command 'gpg' not found. Install GnuPG to verify AWS CLI installer signatures, or install AWS CLI manually from https://aws.amazon.com/cli/".to_string()
            } else {
                format!("Failed to verify {label} signature: {e}")
            }
        })?;
    let combined = combined_output(&output);
    if !output.status_success {
        return Err(format!("{label} signature verification failed: {combined}"));
    }
    if !gpg_output_has_expected_fingerprint(&combined) {
        return Err(format!(
            "{label} signature fingerprint did not match expected AWS CLI key {AWS_CLI_PGP_FINGERPRINT}: {combined}"
        ));
    }
    Ok(())
}

fn gpg_output_has_expected_fingerprint(output: &str) -> bool {
    let compact = output
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_uppercase();
    compact.contains(AWS_CLI_PGP_FINGERPRINT)
}

fn aws_cli_linux_zip_url_for_arch(arch: &str) -> Result<&'static str, String> {
    match arch {
        "x86_64" | "amd64" => Ok(AWS_CLI_LINUX_X86_64_ZIP_URL),
        "aarch64" | "arm64" => Ok(AWS_CLI_LINUX_AARCH64_ZIP_URL),
        other => Err(format!(
            "Automatic AWS CLI v2 install is not supported on Linux architecture '{other}'. Install manually: {}",
            LocalDependency::AwsCliV2.manual_install_url()
        )),
    }
}

fn ssm_plugin_mac_pkg_url_for_arch(arch: &str) -> &'static str {
    match arch {
        "aarch64" | "arm64" => SSM_PLUGIN_MAC_ARM64_PKG_URL,
        _ => SSM_PLUGIN_MAC_X86_64_PKG_URL,
    }
}

fn run_step<R: CommandRunner>(
    runner: &R,
    program: &str,
    args: Vec<String>,
    label: &str,
) -> Result<(), String> {
    println!("  {label}...");
    match runner.status(program, &args) {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!("{label} failed")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            Err(format!("Required command '{program}' not found"))
        }
        Err(e) => Err(format!("{label} failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::io;

    #[derive(Default)]
    struct FakeRunner {
        outputs: HashMap<String, CommandOutput>,
        outputs_by_program: HashMap<String, CommandOutput>,
        missing_outputs: HashSet<String>,
        statuses: HashMap<String, bool>,
        statuses_by_program: HashMap<String, bool>,
    }

    impl FakeRunner {
        fn with_output(mut self, program: &str, args: &[&str], output: CommandOutput) -> Self {
            self.outputs.insert(key(program, args), output);
            self
        }

        fn with_output_for_program(mut self, program: &str, output: CommandOutput) -> Self {
            self.outputs_by_program.insert(program.into(), output);
            self
        }

        fn with_missing(mut self, program: &str, args: &[&str]) -> Self {
            self.missing_outputs.insert(key(program, args));
            self
        }

        fn with_status(mut self, program: &str, args: &[String], ok: bool) -> Self {
            self.statuses.insert(status_key(program, args), ok);
            self
        }

        fn with_status_for_program(mut self, program: &str, ok: bool) -> Self {
            self.statuses_by_program.insert(program.into(), ok);
            self
        }
    }

    impl CommandRunner for FakeRunner {
        fn output(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
            let key = key(program, args);
            if self.missing_outputs.contains(&key) {
                return Err(io::Error::new(io::ErrorKind::NotFound, "missing"));
            }
            self.outputs
                .get(&key)
                .cloned()
                .or_else(|| self.outputs_by_program.get(program).cloned())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing"))
        }

        fn status(&self, program: &str, args: &[String]) -> io::Result<bool> {
            Ok(self
                .statuses
                .get(&status_key(program, args))
                .copied()
                .or_else(|| self.statuses_by_program.get(program).copied())
                .unwrap_or(true))
        }
    }

    fn key(program: &str, args: &[&str]) -> String {
        format!("{program} {}", args.join(" "))
    }

    fn status_key(program: &str, args: &[String]) -> String {
        format!("{program} {}", args.join(" "))
    }

    fn output_with_status(status_success: bool, stdout: &str, stderr: &str) -> CommandOutput {
        CommandOutput {
            status_success,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    fn output(stdout: &str, stderr: &str) -> CommandOutput {
        output_with_status(true, stdout, stderr)
    }

    fn connect_response(command: &str, args: &[&str]) -> PtySpawnSpec {
        PtySpawnSpec {
            command: command.into(),
            args: args.iter().map(|arg| (*arg).into()).collect(),
            env_vars: Default::default(),
            max_session_seconds: None,
        }
    }

    #[test]
    fn aws_cli_v2_version_is_accepted() {
        assert!(is_aws_cli_v2_version(
            "aws-cli/2.15.0 Python/3.11.0 Darwin/23.0 source/arm64"
        ));
    }

    #[test]
    fn aws_cli_v1_version_is_rejected() {
        assert!(!is_aws_cli_v2_version(
            "aws-cli/1.32.0 Python/3.11.0 Darwin/23.0 botocore/1.34.0"
        ));
    }

    #[test]
    fn aws_cli_version_requires_exact_v2_prefix() {
        assert!(!is_aws_cli_v2_version("some-aws-cli/2.15.0"));
        assert!(!is_aws_cli_v2_version("aws-cli/2999.0.0"));
    }

    #[test]
    fn missing_aws_cli_returns_dependency_issue() {
        let runner = FakeRunner::default().with_missing("aws", &["--version"]);
        let issues = check_required_dependencies(&[LocalDependency::AwsCliV2], &runner);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].dependency, LocalDependency::AwsCliV2);
        assert!(issues[0].reason.contains("not found"));
    }

    #[test]
    fn aws_cli_v1_returns_dependency_issue() {
        let runner =
            FakeRunner::default().with_output("aws", &["--version"], output("aws-cli/1.32.0", ""));
        let issues = check_required_dependencies(&[LocalDependency::AwsCliV2], &runner);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].dependency, LocalDependency::AwsCliV2);
        assert!(issues[0].reason.contains("AWS CLI v2 is required"));
    }

    #[test]
    fn eic_requires_aws_cli_and_ssh() {
        let resp = connect_response(
            "aws",
            &[
                "ec2-instance-connect",
                "ssh",
                "--instance-id",
                "i-123",
                "--region",
                "ap-northeast-1",
            ],
        );
        assert_eq!(
            required_dependencies_for_connect(&resp),
            vec![LocalDependency::AwsCliV2, LocalDependency::Ssh]
        );
    }

    #[test]
    fn plain_ssm_requires_aws_cli_and_session_manager_plugin() {
        let resp = connect_response(
            "aws",
            &[
                "ssm",
                "start-session",
                "--target",
                "i-123",
                "--region",
                "ap-northeast-1",
            ],
        );
        assert_eq!(
            required_dependencies_for_connect(&resp),
            vec![
                LocalDependency::AwsCliV2,
                LocalDependency::SessionManagerPlugin
            ]
        );
    }

    #[test]
    fn ecs_exec_requires_aws_cli_and_session_manager_plugin() {
        let resp = connect_response(
            "aws",
            &[
                "ecs",
                "execute-command",
                "--cluster",
                "arn:aws:ecs:us-east-1:111111111111:cluster/prod",
                "--task",
                "arn:aws:ecs:us-east-1:111111111111:task/prod/abc",
                "--container",
                "app",
                "--interactive",
                "--command",
                "/bin/sh",
            ],
        );
        assert_eq!(
            required_dependencies_for_connect(&resp),
            vec![
                LocalDependency::AwsCliV2,
                LocalDependency::SessionManagerPlugin
            ]
        );
    }

    #[test]
    fn ssm_proxy_command_requires_ssh_aws_cli_and_session_manager_plugin() {
        let resp = connect_response(
            "ssh",
            &[
                "-o",
                "ProxyCommand=aws ssm start-session --target %h --document-name AWS-StartSSHSession",
                "-l",
                "ec2-user",
                "i-123",
            ],
        );
        assert_eq!(
            required_dependencies_for_connect(&resp),
            vec![
                LocalDependency::AwsCliV2,
                LocalDependency::Ssh,
                LocalDependency::SessionManagerPlugin
            ]
        );
    }

    #[test]
    fn ssm_proxy_command_detection_tolerates_path_and_spacing() {
        let resp = connect_response(
            "/usr/bin/ssh",
            &[
                "-o",
                "ProxyCommand = aws    ssm   start-session --target %h",
                "-l",
                "ec2-user",
                "i-123",
            ],
        );
        assert_eq!(
            required_dependencies_for_connect(&resp),
            vec![
                LocalDependency::AwsCliV2,
                LocalDependency::Ssh,
                LocalDependency::SessionManagerPlugin
            ]
        );
    }

    #[test]
    fn direct_ssh_requires_only_ssh() {
        let resp = connect_response("ssh", &["ec2-user@10.0.0.1"]);
        assert_eq!(
            required_dependencies_for_connect(&resp),
            vec![LocalDependency::Ssh]
        );
    }

    #[test]
    fn all_present_returns_no_dependency_issues() {
        let runner = FakeRunner::default()
            .with_output("aws", &["--version"], output("aws-cli/2.15.0", ""))
            .with_output("ssh", &["-V"], output("", "OpenSSH_9.0"))
            .with_output(
                "session-manager-plugin",
                &["--version"],
                output("1.2.0.0", ""),
            );
        let deps = vec![
            LocalDependency::AwsCliV2,
            LocalDependency::Ssh,
            LocalDependency::SessionManagerPlugin,
        ];

        assert!(check_required_dependencies(&deps, &runner).is_empty());
    }

    #[test]
    fn fake_install_runner_can_exercise_install_failure() {
        let runner = FakeRunner::default().with_status_for_program("curl", false);

        if matches!(std::env::consts::OS, "macos" | "linux") {
            let err = install_dependency(LocalDependency::AwsCliV2, &runner).unwrap_err();
            assert!(err.contains("Downloading AWS CLI v2 installer failed"));
        }
    }

    #[test]
    fn macos_pkg_signature_must_be_amazon_team() {
        assert!(macos_pkg_signature_is_amazon(
            "Developer ID Installer: AMZN Mobile LLC (94KV3E626L)"
        ));
        assert!(!macos_pkg_signature_is_amazon(
            "Developer ID Installer: Example Corp (ABCDE12345)"
        ));
    }

    #[test]
    fn linux_aws_cli_url_rejects_32_bit_arm() {
        assert_eq!(
            aws_cli_linux_zip_url_for_arch("aarch64").unwrap(),
            AWS_CLI_LINUX_AARCH64_ZIP_URL
        );
        assert!(aws_cli_linux_zip_url_for_arch("arm").is_err());
    }

    #[test]
    fn fake_macos_pkg_verify_checks_team_id() {
        let runner = FakeRunner::default().with_output_for_program(
            "pkgutil",
            output_with_status(
                true,
                "Developer ID Installer: AMZN Mobile LLC (94KV3E626L)",
                "",
            ),
        );
        let pkg = std::path::Path::new("/tmp/example.pkg");

        assert!(verify_macos_pkg_signature(&runner, pkg, "example").is_ok());
    }

    #[test]
    fn macos_pkg_verify_rejects_failed_signature_check() {
        let runner = FakeRunner::default().with_output_for_program(
            "pkgutil",
            output_with_status(false, "", "Package example.pkg: Status: no signature"),
        );
        let pkg = std::path::Path::new("/tmp/example.pkg");

        let err = verify_macos_pkg_signature(&runner, pkg, "example").unwrap_err();
        assert!(err.contains("signature verification failed"));
    }

    #[test]
    fn macos_pkg_verify_rejects_unsigned_output() {
        let runner = FakeRunner::default().with_output_for_program(
            "pkgutil",
            output_with_status(true, "Package example.pkg: Status: no signature", ""),
        );
        let pkg = std::path::Path::new("/tmp/example.pkg");

        let err = verify_macos_pkg_signature(&runner, pkg, "example").unwrap_err();
        assert!(err.contains("not signed by expected AWS Developer ID team"));
    }

    #[test]
    fn gpg_output_requires_expected_fingerprint() {
        assert!(gpg_output_has_expected_fingerprint(&format!(
            "[GNUPG:] VALIDSIG {AWS_CLI_PGP_FINGERPRINT} 2026-01-01"
        )));
        assert!(gpg_output_has_expected_fingerprint(
            "Primary key fingerprint: FB5D B77F D5C1 18B8 0511 ADA8 A631 0ACC 4672 475C"
        ));
        assert!(!gpg_output_has_expected_fingerprint(
            "Primary key fingerprint: 0000 1111 2222 3333 4444 5555 6666 7777 8888 9999"
        ));
    }

    #[test]
    fn gpg_verify_reports_missing_gnupg() {
        let runner = FakeRunner::default();

        let err = verify_gpg_signature(
            &runner,
            std::path::Path::new("/tmp/gnupg"),
            std::path::Path::new("/tmp/awscliv2.zip"),
            std::path::Path::new("/tmp/awscliv2.sig"),
            "AWS CLI v2 installer",
        )
        .unwrap_err();

        assert!(err.contains("Install GnuPG"));
        assert!(err.contains("https://aws.amazon.com/cli/"));
    }

    #[test]
    fn ensure_gpg_available_reports_manual_install_hint() {
        let runner = FakeRunner::default();

        let err = ensure_gpg_available(&runner).unwrap_err();

        assert!(err.contains("Install GnuPG"));
        assert!(err.contains("https://aws.amazon.com/cli/"));
    }

    #[test]
    fn ensure_gpg_available_rejects_nonzero_version_check() {
        let runner = FakeRunner::default().with_output(
            "gpg",
            &["--version"],
            output_with_status(false, "", "gpg: corrupted config"),
        );

        let err = ensure_gpg_available(&runner).unwrap_err();

        assert!(err.contains("Required command 'gpg' failed"));
        assert!(err.contains("corrupted config"));
    }

    #[test]
    fn gpg_verify_rejects_failed_signature() {
        let runner = FakeRunner::default().with_output_for_program(
            "gpg",
            output_with_status(false, "", "BAD signature from AWS CLI Team"),
        );

        let err = verify_gpg_signature(
            &runner,
            std::path::Path::new("/tmp/gnupg"),
            std::path::Path::new("/tmp/awscliv2.zip"),
            std::path::Path::new("/tmp/awscliv2.sig"),
            "AWS CLI v2 installer",
        )
        .unwrap_err();

        assert!(err.contains("signature verification failed"));
    }

    #[test]
    fn gpg_verify_rejects_unexpected_fingerprint() {
        let runner = FakeRunner::default().with_output_for_program(
            "gpg",
            output_with_status(
                true,
                "[GNUPG:] VALIDSIG 0000111122223333444455556666777788889999",
                "",
            ),
        );

        let err = verify_gpg_signature(
            &runner,
            std::path::Path::new("/tmp/gnupg"),
            std::path::Path::new("/tmp/awscliv2.zip"),
            std::path::Path::new("/tmp/awscliv2.sig"),
            "AWS CLI v2 installer",
        )
        .unwrap_err();

        assert!(err.contains("signature fingerprint did not match"));
    }

    #[test]
    fn aws_cli_zip_signature_rejects_gpg_verify_failure() {
        let workspace = TempWorkspace::new("canopy-test-awscli-signature").unwrap();
        let zip = workspace.join("awscliv2.zip");
        let sig = workspace.join("awscliv2.sig");
        let runner = FakeRunner::default()
            .with_output("gpg", &["--version"], output("gpg (GnuPG) 2.4.0", ""))
            .with_output_for_program("gpg", output_with_status(false, "", "BAD signature"));

        let err = verify_aws_cli_zip_signature(&runner, &workspace, &zip, &sig).unwrap_err();

        assert!(err.contains("signature verification failed"));
    }

    #[test]
    fn gpg_verify_accepts_expected_fingerprint() {
        let runner = FakeRunner::default().with_output_for_program(
            "gpg",
            output_with_status(
                true,
                &format!("[GNUPG:] VALIDSIG {AWS_CLI_PGP_FINGERPRINT}"),
                "",
            ),
        );

        assert!(verify_gpg_signature(
            &runner,
            std::path::Path::new("/tmp/gnupg"),
            std::path::Path::new("/tmp/awscliv2.zip"),
            std::path::Path::new("/tmp/awscliv2.sig"),
            "AWS CLI v2 installer",
        )
        .is_ok());
    }
}
