use std::{
    env, fs,
    fs::File,
    io,
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    path::{Component, Path, PathBuf},
    process::Stdio,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use reqwest::redirect::Policy;
use shared::dto::{
    entitlements::{
        mcp_ec2_http_url_builtin_deny_reason, mcp_ec2_journal_unit_builtin_deny_reason,
        mcp_ec2_log_path_builtin_deny_reason, mcp_ec2_network_host_builtin_deny_reason,
    },
    mcp::{McpEc2DiagnosticCommand, McpEc2DnsRecordType},
};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

use control_plane::services::mcp_ec2_diagnostics::{
    format_mcp_ec2_diagnostic_output, open_mcp_ec2_diagnostic_command_spec_ref_for_helper,
};

const DEFAULT_KEY_FILE: &str = "/etc/canopy/mcp-ec2-command-spec-key";
const KEY_ENV: &str = "CANOPY_MCP_EC2_COMMAND_SPEC_KEY";
const KEY_FILE_ENV: &str = "CANOPY_MCP_EC2_COMMAND_SPEC_KEY_FILE";
const HELPER_OUTPUT_MAX_BYTES: usize = 16 * 1024;
const HELPER_RAW_OUTPUT_MAX_BYTES: usize = 16 * 1024;
const HELPER_MAX_LOG_LINE_BYTES: usize = 64 * 1024;
const HELPER_MAX_GREP_SCAN_BYTES: usize = 1024 * 1024;
const DNS_LOOKUP_TIMEOUT_SECONDS: u64 = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
struct HelperArgs {
    mcp_ec2_command_id: String,
    instance_id: String,
    account_id: String,
    region: String,
    command_spec_ref: String,
    helper_version: String,
}

#[tokio::main]
async fn main() {
    match run().await {
        Ok(output) => {
            emit_output(&output, false);
        }
        Err(err) => {
            emit_output(&format!("canopy_ec2_diagnostics_error: {err}"), true);
            std::process::exit(1);
        }
    }
}

async fn run() -> Result<String> {
    let args = parse_args(env::args().skip(1))?;
    let key_material = load_key_material()?;
    let payload = open_mcp_ec2_diagnostic_command_spec_ref_for_helper(
        &key_material,
        &args.command_spec_ref,
        &args.helper_version,
        &args.mcp_ec2_command_id,
        &args.instance_id,
        &args.account_id,
        &args.region,
        Utc::now(),
    )
    .context("invalid_command_spec_ref")?;

    execute_command(
        &payload.command,
        payload.private_target_ref.as_deref(),
        payload.log_safe_prefix.as_deref(),
    )
    .await
}

fn parse_args<I, S>(args: I) -> Result<HelperArgs>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut mcp_ec2_command_id = None;
    let mut instance_id = None;
    let mut account_id = None;
    let mut region = None;
    let mut command_spec_ref = None;
    let mut helper_version = None;
    let mut iter = args.into_iter().map(Into::into);

    while let Some(flag) = iter.next() {
        let target = match flag.as_str() {
            "--mcp-ec2-command-id" => &mut mcp_ec2_command_id,
            "--instance-id" => &mut instance_id,
            "--account-id" => &mut account_id,
            "--region" => &mut region,
            "--command-spec-ref" => &mut command_spec_ref,
            "--helper-version" => &mut helper_version,
            _ => bail!("unknown_argument"),
        };
        if target.is_some() {
            bail!("duplicate_argument");
        }
        let value = iter
            .next()
            .ok_or_else(|| anyhow!("missing_argument_value"))?;
        if value.trim().is_empty() {
            bail!("empty_argument_value");
        }
        *target = Some(value);
    }

    Ok(HelperArgs {
        mcp_ec2_command_id: mcp_ec2_command_id
            .ok_or_else(|| anyhow!("missing_mcp_ec2_command_id"))?,
        instance_id: instance_id.ok_or_else(|| anyhow!("missing_instance_id"))?,
        account_id: account_id.ok_or_else(|| anyhow!("missing_account_id"))?,
        region: region.ok_or_else(|| anyhow!("missing_region"))?,
        command_spec_ref: command_spec_ref.ok_or_else(|| anyhow!("missing_command_spec_ref"))?,
        helper_version: helper_version.ok_or_else(|| anyhow!("missing_helper_version"))?,
    })
}

fn load_key_material() -> Result<String> {
    if let Ok(value) = env::var(KEY_ENV) {
        let trimmed = trim_key_material(&value);
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    let key_file = env::var(KEY_FILE_ENV).unwrap_or_else(|_| DEFAULT_KEY_FILE.to_string());
    let contents = fs::read_to_string(&key_file).context("command_spec_key_unavailable")?;
    let trimmed = trim_key_material(&contents);
    if trimmed.is_empty() {
        bail!("command_spec_key_empty");
    }
    Ok(trimmed.to_string())
}

fn trim_key_material(value: &str) -> &str {
    value.trim_matches(|ch| ch == '\n' || ch == '\r')
}

async fn execute_command(
    command: &McpEc2DiagnosticCommand,
    private_target_ref: Option<&str>,
    log_safe_prefix: Option<&str>,
) -> Result<String> {
    match command {
        McpEc2DiagnosticCommand::TailLog { path, lines } => {
            run_tail_log(path, *lines, log_safe_prefix).await
        }
        McpEc2DiagnosticCommand::GrepLog {
            path,
            literal_pattern,
            case_insensitive,
            max_matches,
        } => {
            run_grep_log(
                path,
                literal_pattern,
                *case_insensitive,
                *max_matches,
                log_safe_prefix,
            )
            .await
        }
        McpEc2DiagnosticCommand::JournalctlUnit { unit, since, lines } => {
            run_journalctl_unit(unit, since, *lines).await
        }
        McpEc2DiagnosticCommand::HttpHead {
            url,
            max_time_seconds,
        } => run_http_head(url, *max_time_seconds, private_target_ref).await,
        McpEc2DiagnosticCommand::TcpProbe {
            host,
            port,
            timeout_seconds,
        } => run_tcp_probe(host, *port, *timeout_seconds, private_target_ref).await,
        McpEc2DiagnosticCommand::DnsLookup { host, record_type } => {
            run_dns_lookup(host, record_type, private_target_ref).await
        }
    }
}

async fn run_tail_log(path: &str, lines: u16, log_safe_prefix: Option<&str>) -> Result<String> {
    if lines == 0 {
        bail!("invalid_lines");
    }
    let mut verified = open_verified_log_file(path, log_safe_prefix)?;
    read_tail_from_file(&mut verified.file, lines, HELPER_RAW_OUTPUT_MAX_BYTES)
}

async fn run_grep_log(
    path: &str,
    literal_pattern: &str,
    case_insensitive: bool,
    max_matches: u16,
    log_safe_prefix: Option<&str>,
) -> Result<String> {
    if max_matches == 0 || literal_pattern.trim().len() < 3 || literal_pattern.trim() == "." {
        bail!("invalid_grep_request");
    }
    let mut verified = open_verified_log_file(path, log_safe_prefix)?;
    grep_from_file(
        &mut verified.file,
        literal_pattern,
        case_insensitive,
        max_matches,
        HELPER_RAW_OUTPUT_MAX_BYTES,
        HELPER_MAX_GREP_SCAN_BYTES,
    )
}

async fn run_journalctl_unit(unit: &str, since: &str, lines: u16) -> Result<String> {
    if lines == 0 || mcp_ec2_journal_unit_builtin_deny_reason(unit).is_some() {
        bail!("invalid_journal_request");
    }
    let line_arg = lines.to_string();
    let since_arg = journal_since_arg(since)?;
    run_fixed_command(
        &["/usr/bin/journalctl", "/bin/journalctl"],
        &[
            "--no-pager",
            "--unit",
            unit,
            "--since",
            since_arg.as_str(),
            "-n",
            line_arg.as_str(),
        ],
        Duration::from_secs(20),
        &[0],
    )
    .await
}

async fn run_http_head(
    url: &str,
    max_time_seconds: u8,
    private_target_ref: Option<&str>,
) -> Result<String> {
    if max_time_seconds == 0
        || mcp_ec2_http_url_builtin_deny_reason(url, private_target_ref).is_some()
    {
        bail!("invalid_http_target");
    }
    let parsed_url = reqwest::Url::parse(url).context("invalid_http_url")?;
    let host = parsed_url
        .host_str()
        .ok_or_else(|| anyhow!("http_host_missing"))?;
    let port = parsed_url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("http_port_missing"))?;
    let addresses = resolve_socket_addresses(host, port)?;
    validate_resolved_addresses(host, &addresses, private_target_ref)?;

    let timeout_duration = Duration::from_secs(max_time_seconds as u64);
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .resolve_to_addrs(host, &addresses)
        .timeout(timeout_duration)
        .build()
        .context("http_client_unavailable")?;
    let response = client.head(url).send().await.context("http_head_failed")?;
    let mut output = format!("status: {}\n", response.status());
    if let Some(content_length) = response.content_length() {
        output.push_str(&format!("content_length: {content_length}\n"));
    }
    if let Some(content_type) = response.headers().get(reqwest::header::CONTENT_TYPE) {
        if let Ok(content_type) = content_type.to_str() {
            output.push_str(&format!("content_type: {content_type}\n"));
        }
    }
    Ok(output)
}

async fn run_tcp_probe(
    host: &str,
    port: u16,
    timeout_seconds: u8,
    private_target_ref: Option<&str>,
) -> Result<String> {
    if port == 0
        || timeout_seconds == 0
        || mcp_ec2_network_host_builtin_deny_reason(host, private_target_ref).is_some()
    {
        bail!("invalid_tcp_target");
    }
    let timeout_duration = Duration::from_secs(timeout_seconds as u64);
    let addresses = resolve_socket_addresses(host, port)?;
    validate_resolved_addresses(host, &addresses, private_target_ref)?;
    let mut last_error = None;
    for address in &addresses {
        match TcpStream::connect_timeout(address, timeout_duration) {
            Ok(_) => {
                return Ok(format!("tcp_connect: ok\nremote_addr: {address}\n"));
            }
            Err(err) => {
                last_error = Some(err);
            }
        }
    }
    Err(last_error
        .map(|err| anyhow!("tcp_connect_failed: {err}"))
        .unwrap_or_else(|| anyhow!("tcp_resolve_failed")))
}

async fn run_dns_lookup(
    host: &str,
    record_type: &McpEc2DnsRecordType,
    private_target_ref: Option<&str>,
) -> Result<String> {
    if mcp_ec2_network_host_builtin_deny_reason(host, private_target_ref).is_some() {
        bail!("invalid_dns_target");
    }

    if let Some(dig) = first_existing_executable(&["/usr/bin/dig", "/bin/dig"]) {
        let record_type_arg = dns_record_type_arg(record_type);
        let output = run_fixed_command(
            &[path_to_str(&dig)?],
            &["+short", host, record_type_arg],
            Duration::from_secs(DNS_LOOKUP_TIMEOUT_SECONDS),
            &[0],
        )
        .await?;
        validate_dns_output(&output, record_type, private_target_ref)?;
        return Ok(output);
    }

    match record_type {
        McpEc2DnsRecordType::A | McpEc2DnsRecordType::Aaaa => {
            run_std_dns_lookup(host, record_type, private_target_ref)
        }
        McpEc2DnsRecordType::Cname => bail!("dns_cname_lookup_unavailable"),
    }
}

fn run_std_dns_lookup(
    host: &str,
    record_type: &McpEc2DnsRecordType,
    private_target_ref: Option<&str>,
) -> Result<String> {
    let mut output = String::new();
    let mut addresses = resolve_socket_addresses(host, 0)?;
    validate_resolved_addresses(host, &addresses, private_target_ref)?;
    addresses.sort();
    addresses.dedup();
    for address in addresses {
        match (record_type, address.ip()) {
            (McpEc2DnsRecordType::A, IpAddr::V4(ip)) => {
                output.push_str(&format!("{ip}\n"));
            }
            (McpEc2DnsRecordType::Aaaa, IpAddr::V6(ip)) => {
                output.push_str(&format!("{ip}\n"));
            }
            _ => {}
        }
    }
    Ok(output)
}

async fn run_fixed_command(
    candidates: &[&str],
    args: &[&str],
    timeout_duration: Duration,
    allowed_exit_codes: &[i32],
) -> Result<String> {
    let executable =
        first_existing_executable(candidates).ok_or_else(|| anyhow!("tool_unavailable"))?;
    let mut command = Command::new(&executable);
    command.kill_on_drop(true);
    command
        .args(args)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().context("tool_execution_failed")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("stdout_missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("stderr_missing"))?;
    let output = timeout(timeout_duration, async move {
        let stdout_task = tokio::spawn(read_async_capped(stdout, HELPER_RAW_OUTPUT_MAX_BYTES));
        let stderr_task = tokio::spawn(read_async_capped(stderr, HELPER_RAW_OUTPUT_MAX_BYTES));
        let status = child.wait().await.context("tool_wait_failed")?;
        let stdout = stdout_task.await.context("stdout_task_failed")??;
        let stderr = stderr_task.await.context("stderr_task_failed")??;
        Ok::<_, anyhow::Error>((status, stdout, stderr))
    })
    .await
    .map_err(|_| anyhow!("tool_timeout"))?
    .context("tool_execution_failed")?;
    let (status, stdout, stderr) = output;
    let exit_code = status.code().unwrap_or(-1);
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&stdout.bytes));
    if stdout.truncated {
        append_capped(
            &mut combined,
            "\n[stdout truncated]\n",
            HELPER_RAW_OUTPUT_MAX_BYTES,
        );
    }
    if !stderr.bytes.is_empty() || stderr.truncated {
        if !combined.is_empty() && !combined.ends_with('\n') {
            combined.push('\n');
        }
        append_capped(&mut combined, "[stderr]\n", HELPER_RAW_OUTPUT_MAX_BYTES);
        append_capped(
            &mut combined,
            &String::from_utf8_lossy(&stderr.bytes),
            HELPER_RAW_OUTPUT_MAX_BYTES,
        );
        if stderr.truncated {
            append_capped(
                &mut combined,
                "\n[stderr truncated]\n",
                HELPER_RAW_OUTPUT_MAX_BYTES,
            );
        }
    }
    if !allowed_exit_codes.contains(&exit_code) {
        if !combined.is_empty() && !combined.ends_with('\n') {
            combined.push('\n');
        }
        append_capped(
            &mut combined,
            &format!("exit_code: {exit_code}\n"),
            HELPER_RAW_OUTPUT_MAX_BYTES,
        );
        bail!("tool_failed: {combined}");
    }
    Ok(combined)
}

struct VerifiedLogFile {
    file: File,
    #[cfg(test)]
    canonical_path: PathBuf,
}

fn open_verified_log_file(path: &str, log_safe_prefix: Option<&str>) -> Result<VerifiedLogFile> {
    if mcp_ec2_log_path_builtin_deny_reason(path).is_some() {
        bail!("denied_log_path");
    }
    let safe_prefix = log_safe_prefix.ok_or_else(|| anyhow!("log_safe_prefix_missing"))?;
    if mcp_ec2_log_path_builtin_deny_reason(safe_prefix).is_some() {
        bail!("denied_log_safe_prefix");
    }
    let requested = Path::new(path);
    if !requested.is_absolute() || has_disallowed_path_component(requested) {
        bail!("invalid_log_path");
    }
    let requested_safe_prefix = Path::new(safe_prefix);
    if !requested_safe_prefix.is_absolute() || has_disallowed_path_component(requested_safe_prefix)
    {
        bail!("invalid_log_safe_prefix");
    }
    if path_has_symlink_component(requested_safe_prefix)? {
        bail!("log_safe_prefix_symlink_denied");
    }

    let file = open_log_file_no_follow(requested).context("log_path_open_failed")?;
    let opened_metadata = file.metadata().context("log_path_metadata_unavailable")?;
    validate_opened_log_metadata(&opened_metadata)?;
    let canonical = fs::canonicalize(requested).context("log_path_canonicalize_failed")?;
    let canonical_metadata =
        fs::metadata(&canonical).context("log_path_canonical_metadata_failed")?;
    if !same_file(&opened_metadata, &canonical_metadata) {
        bail!("log_path_changed_during_validation");
    }
    let canonical_text = path_to_str(&canonical)?;
    if mcp_ec2_log_path_builtin_deny_reason(canonical_text).is_some() {
        bail!("denied_canonical_log_path");
    }
    let canonical_safe_prefix =
        fs::canonicalize(requested_safe_prefix).context("log_safe_prefix_canonicalize_failed")?;
    if !canonical.starts_with(&canonical_safe_prefix) {
        bail!("log_path_escape_denied");
    }
    Ok(VerifiedLogFile {
        file,
        #[cfg(test)]
        canonical_path: canonical,
    })
}

#[cfg(test)]
fn canonical_safe_log_path(path: &str, log_safe_prefix: Option<&str>) -> Result<PathBuf> {
    open_verified_log_file(path, log_safe_prefix).map(|verified| verified.canonical_path)
}

#[cfg(unix)]
fn open_log_file_no_follow(path: &Path) -> io::Result<File> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(unix))]
fn open_log_file_no_follow(path: &Path) -> io::Result<File> {
    fs::OpenOptions::new().read(true).open(path)
}

#[cfg(unix)]
fn validate_opened_log_metadata(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file() {
        bail!("log_path_not_regular_file");
    }
    if metadata.nlink() > 1 {
        bail!("log_path_hardlink_denied");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_opened_log_metadata(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file() {
        bail!("log_path_not_regular_file");
    }
    Ok(())
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    true
}

fn read_tail_from_file(file: &mut File, lines: u16, max_bytes: usize) -> Result<String> {
    let mut pos = file.seek(SeekFrom::End(0)).context("log_seek_failed")?;
    let mut chunks = Vec::new();
    let mut total = 0_usize;
    let mut newline_count = 0_usize;
    let requested_lines = usize::from(lines);

    while pos > 0 && total < max_bytes && newline_count <= requested_lines {
        let read_size = (pos as usize).min(8192).min(max_bytes - total);
        pos -= read_size as u64;
        file.seek(SeekFrom::Start(pos)).context("log_seek_failed")?;
        let mut chunk = vec![0_u8; read_size];
        file.read_exact(&mut chunk).context("log_read_failed")?;
        newline_count += chunk.iter().filter(|byte| **byte == b'\n').count();
        total += chunk.len();
        chunks.push(chunk);
    }

    chunks.reverse();
    let mut data = Vec::with_capacity(total);
    for chunk in chunks {
        data.extend(chunk);
    }
    if data.is_empty() {
        return Ok(String::new());
    }

    let mut seen = 0_usize;
    let mut start = 0_usize;
    let mut ignore_trailing_newline = data.last() == Some(&b'\n');
    for index in (0..data.len()).rev() {
        if data[index] == b'\n' {
            if ignore_trailing_newline {
                ignore_trailing_newline = false;
                continue;
            }
            seen += 1;
            if seen == requested_lines {
                start = index + 1;
                break;
            }
        }
    }

    Ok(String::from_utf8_lossy(&data[start..]).into_owned())
}

fn grep_from_file(
    file: &mut File,
    literal_pattern: &str,
    case_insensitive: bool,
    max_matches: u16,
    max_bytes: usize,
    max_scan_bytes: usize,
) -> Result<String> {
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut output = String::new();
    let mut matches = 0_u16;
    let mut scanned = 0_usize;
    let pattern = if case_insensitive {
        literal_pattern.to_ascii_lowercase()
    } else {
        literal_pattern.to_string()
    };

    while matches < max_matches {
        line.clear();
        let bytes_read = read_line_capped(&mut reader, &mut line, HELPER_MAX_LOG_LINE_BYTES)
            .context("log_read_failed")?;
        if bytes_read == 0 {
            break;
        }
        scanned = scanned.saturating_add(bytes_read);
        if scanned > max_scan_bytes {
            bail!("grep_scan_limit_exceeded");
        }
        let line_text = String::from_utf8_lossy(&line);
        let is_match = if case_insensitive {
            line_text.to_ascii_lowercase().contains(&pattern)
        } else {
            line_text.contains(&pattern)
        };
        if is_match {
            append_capped(&mut output, &line_text, max_bytes);
            matches = matches.saturating_add(1);
            if output.len() >= max_bytes {
                break;
            }
        }
    }

    Ok(output)
}

fn read_line_capped<R: BufRead>(
    reader: &mut R,
    output: &mut Vec<u8>,
    cap: usize,
) -> io::Result<usize> {
    let mut total = 0_usize;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(total);
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1)
            .unwrap_or(available.len());
        let remaining = cap.saturating_sub(output.len());
        if remaining > 0 {
            output.extend_from_slice(&available[..take.min(remaining)]);
        }
        total = total.saturating_add(take);
        let found_newline = available[..take].last() == Some(&b'\n');
        reader.consume(take);
        if found_newline {
            return Ok(total);
        }
    }
}

#[derive(Debug)]
struct CappedAsyncOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

async fn read_async_capped<R>(mut reader: R, cap: usize) -> io::Result<CappedAsyncOutput>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(cap.min(8192));
    let mut truncated = false;
    let mut chunk = [0_u8; 8192];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        let remaining = cap.saturating_sub(bytes.len());
        if remaining > 0 {
            bytes.extend_from_slice(&chunk[..read.min(remaining)]);
        }
        if read > remaining {
            truncated = true;
        }
    }
    Ok(CappedAsyncOutput { bytes, truncated })
}

fn append_capped(output: &mut String, value: &str, cap: usize) -> bool {
    if output.len() >= cap {
        return true;
    }
    let remaining = cap - output.len();
    if value.len() <= remaining {
        output.push_str(value);
        return false;
    }
    let mut end = remaining;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    output.push_str(&value[..end]);
    true
}

fn has_disallowed_path_component(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component,
            Component::CurDir | Component::ParentDir | Component::Prefix(_)
        )
    })
}

fn path_has_symlink_component(path: &Path) -> Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(err) => return Err(err).context("path_component_metadata_failed"),
        }
    }
    Ok(false)
}

fn resolve_socket_addresses(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    (host, port)
        .to_socket_addrs()
        .map(|iter| iter.collect::<Vec<_>>())
        .map_err(|err| anyhow!("dns_resolve_failed: {err}"))
        .and_then(|addresses| {
            if addresses.is_empty() {
                Err(anyhow!("dns_resolve_empty"))
            } else {
                Ok(addresses)
            }
        })
}

fn validate_resolved_addresses(
    host: &str,
    addresses: &[SocketAddr],
    private_target_ref: Option<&str>,
) -> Result<()> {
    for address in addresses {
        validate_resolved_ip(host, address.ip(), private_target_ref)?;
    }
    Ok(())
}

fn validate_resolved_ip(host: &str, ip: IpAddr, private_target_ref: Option<&str>) -> Result<()> {
    let ip_text = ip.to_string();
    if mcp_ec2_network_host_builtin_deny_reason(&ip_text, None)
        == Some("private_network_host_requires_ref")
    {
        let host_ip = parse_host_ip(host).ok_or_else(|| anyhow!("private_dns_rebind_denied"))?;
        if normalize_ip(host_ip) != normalize_ip(ip) {
            bail!("private_dns_rebind_denied");
        }
        if mcp_ec2_network_host_builtin_deny_reason(&ip_text, private_target_ref).is_some() {
            bail!("resolved_target_denied");
        }
        return Ok(());
    }
    if mcp_ec2_network_host_builtin_deny_reason(&ip_text, private_target_ref).is_some() {
        bail!("resolved_target_denied");
    }
    Ok(())
}

fn parse_host_ip(host: &str) -> Option<IpAddr> {
    host.trim()
        .trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .ok()
        .map(normalize_ip)
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(addr) => addr
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(addr)),
        IpAddr::V4(addr) => IpAddr::V4(addr),
    }
}

fn validate_dns_output(
    output: &str,
    record_type: &McpEc2DnsRecordType,
    private_target_ref: Option<&str>,
) -> Result<()> {
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        match record_type {
            McpEc2DnsRecordType::A | McpEc2DnsRecordType::Aaaa => {
                let ip = line.parse::<IpAddr>().context("dns_output_not_ip")?;
                validate_resolved_ip("", ip, private_target_ref)
                    .context("dns_output_target_denied")?;
            }
            McpEc2DnsRecordType::Cname => {
                let cname = line.trim_end_matches('.');
                if mcp_ec2_network_host_builtin_deny_reason(cname, None)
                    == Some("private_network_host_requires_ref")
                {
                    bail!("dns_output_target_denied");
                }
                if mcp_ec2_network_host_builtin_deny_reason(cname, private_target_ref).is_some() {
                    bail!("dns_output_target_denied");
                }
            }
        }
    }
    Ok(())
}

fn first_existing_executable(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().map(PathBuf::from).find(|path| {
        fs::metadata(path)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
    })
}

fn path_to_str(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| anyhow!("path_not_utf8"))
}

fn journal_since_arg(since: &str) -> Result<String> {
    let seconds = since
        .strip_suffix('s')
        .ok_or_else(|| anyhow!("invalid_since"))?
        .parse::<u64>()
        .context("invalid_since")?;
    if seconds == 0 {
        bail!("invalid_since");
    }
    Ok(format!("{seconds} seconds ago"))
}

fn dns_record_type_arg(record_type: &McpEc2DnsRecordType) -> &'static str {
    match record_type {
        McpEc2DnsRecordType::A => "A",
        McpEc2DnsRecordType::Aaaa => "AAAA",
        McpEc2DnsRecordType::Cname => "CNAME",
    }
}

fn emit_output(raw: &str, stderr: bool) {
    let formatted = format_mcp_ec2_diagnostic_output(raw, HELPER_OUTPUT_MAX_BYTES);
    if stderr {
        eprintln!("{}", formatted.output_text);
    } else {
        println!("{}", formatted.output_text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn visible_tempdir() -> TempDir {
        tempfile::Builder::new()
            .prefix("canopy-ec2-helper-")
            .tempdir_in("/private/tmp")
            .unwrap_or_else(|_| {
                tempfile::Builder::new()
                    .prefix("canopy-ec2-helper-")
                    .tempdir()
                    .unwrap()
            })
    }

    #[test]
    fn parse_args_requires_exact_known_arguments() {
        let args = parse_args([
            "--mcp-ec2-command-id",
            "mcp_ec2_01",
            "--instance-id",
            "i-1234567890abcdef0",
            "--account-id",
            "123456789012",
            "--region",
            "ap-northeast-1",
            "--command-spec-ref",
            "canopy-ec2-spec:v1:nonce.ciphertext",
            "--helper-version",
            "2026-06-04.1",
        ])
        .unwrap();
        assert_eq!(args.instance_id, "i-1234567890abcdef0");

        assert!(parse_args(["--unknown", "value"]).is_err());
    }

    #[test]
    fn journal_since_arg_converts_control_plane_normalized_seconds() {
        assert_eq!(journal_since_arg("600s").unwrap(), "600 seconds ago");
        assert!(journal_since_arg("0s").is_err());
        assert!(journal_since_arg("yesterday").is_err());
    }

    #[test]
    fn dns_output_validation_filters_record_family() {
        validate_dns_output("203.0.113.10\n", &McpEc2DnsRecordType::A, None).unwrap();
        assert!(validate_dns_output("127.0.0.1\n", &McpEc2DnsRecordType::A, None).is_err());
        assert!(validate_dns_output("not-an-ip\n", &McpEc2DnsRecordType::A, None).is_err());
    }

    #[test]
    fn resolved_address_validation_blocks_loopback_without_private_ref() {
        let loopback: SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert!(validate_resolved_addresses("127.0.0.1", &[loopback], None).is_err());
        assert!(validate_resolved_addresses("127.0.0.1", &[loopback], Some("target-ref")).is_err());
    }

    #[test]
    fn resolved_address_validation_blocks_private_without_private_ref() {
        let private: SocketAddr = "10.0.0.5:443".parse().unwrap();
        assert!(validate_resolved_addresses("10.0.0.5", &[private], None).is_err());
        assert!(validate_resolved_addresses("10.0.0.5", &[private], Some("target-ref")).is_ok());
        assert!(
            validate_resolved_addresses("service.internal", &[private], Some("target-ref"))
                .is_err()
        );
    }

    #[test]
    fn canonical_log_path_rejects_sensitive_names() {
        assert!(canonical_safe_log_path("/var/log/auth.log", Some("/var/log")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn canonical_log_path_rejects_symlink_file() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().unwrap();
        let target = tempdir.path().join("app.log");
        let link = tempdir.path().join("link.log");
        fs::write(&target, "ok\n").unwrap();
        symlink(&target, &link).unwrap();

        assert!(canonical_safe_log_path(
            path_to_str(&link).unwrap(),
            Some(path_to_str(tempdir.path()).unwrap())
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn canonical_log_path_rejects_parent_symlink_escape() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().unwrap();
        let safe_root = tempdir.path().join("safe");
        let outside = tempdir.path().join("outside");
        let linked_dir = safe_root.join("linked");
        fs::create_dir_all(&safe_root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("app.log"), "secret\n").unwrap();
        symlink(&outside, &linked_dir).unwrap();

        assert!(canonical_safe_log_path(
            path_to_str(&linked_dir.join("app.log")).unwrap(),
            Some(path_to_str(&safe_root).unwrap())
        )
        .is_err());
    }

    #[test]
    fn canonical_log_path_accepts_regular_file_under_safe_prefix() {
        let tempdir = visible_tempdir();
        let safe_root = tempdir.path().join("safe");
        let log_path = safe_root.join("app.log");
        fs::create_dir_all(&safe_root).unwrap();
        fs::write(&log_path, "ok\n").unwrap();

        let canonical = canonical_safe_log_path(
            path_to_str(&log_path).unwrap(),
            Some(path_to_str(&safe_root).unwrap()),
        )
        .unwrap();
        assert_eq!(canonical, fs::canonicalize(&log_path).unwrap());
    }

    #[tokio::test]
    async fn tail_log_reads_verified_file_without_external_tail() {
        let tempdir = visible_tempdir();
        let safe_root = tempdir.path().join("safe");
        let log_path = safe_root.join("app.log");
        fs::create_dir_all(&safe_root).unwrap();
        fs::write(&log_path, "one\ntwo\nthree\n").unwrap();

        let output = run_tail_log(
            path_to_str(&log_path).unwrap(),
            2,
            Some(path_to_str(&safe_root).unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(output, "two\nthree\n");
    }

    #[tokio::test]
    async fn grep_log_reads_verified_file_with_output_cap() {
        let tempdir = visible_tempdir();
        let safe_root = tempdir.path().join("safe");
        let log_path = safe_root.join("app.log");
        fs::create_dir_all(&safe_root).unwrap();
        fs::write(&log_path, "alpha\nrequest-id=1\nREQUEST-ID=2\n").unwrap();

        let output = run_grep_log(
            path_to_str(&log_path).unwrap(),
            "request-id",
            true,
            2,
            Some(path_to_str(&safe_root).unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(output, "request-id=1\nREQUEST-ID=2\n");
    }

    #[tokio::test]
    async fn grep_log_fails_closed_after_scan_cap_without_match() {
        let tempdir = visible_tempdir();
        let safe_root = tempdir.path().join("safe");
        let log_path = safe_root.join("app.log");
        fs::create_dir_all(&safe_root).unwrap();
        fs::write(
            &log_path,
            "no-match\n".repeat((HELPER_MAX_GREP_SCAN_BYTES / 9) + 2),
        )
        .unwrap();

        let err = run_grep_log(
            path_to_str(&log_path).unwrap(),
            "request-id",
            false,
            1,
            Some(path_to_str(&safe_root).unwrap()),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("grep_scan_limit_exceeded"));
    }

    #[test]
    fn trim_key_material_preserves_inner_spaces() {
        assert_eq!(
            trim_key_material(" key with spaces \n"),
            " key with spaces "
        );
    }

    #[test]
    fn io_error_does_not_require_displaying_secret_material() {
        let err = io::Error::new(io::ErrorKind::NotFound, "not found");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
