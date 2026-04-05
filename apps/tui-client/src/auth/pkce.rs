use crate::api_client::{generate_code_verifier, ApiClient};
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Complete PKCE flow:
/// 1. Start local callback server
/// 2. Get authorize URL from control-plane
/// 3. Open browser
/// 4. Wait for callback with authorization code
/// 5. Exchange code for token via control-plane
/// 6. Return internal access token
pub async fn start_pkce_flow(api: &ApiClient, callback_port: u16) -> Result<String> {
    let code_verifier = generate_code_verifier();
    let redirect_uri = format!("http://localhost:{}/callback", callback_port);

    // Bind the callback listener BEFORE opening the browser, so a fast
    // IdP redirect (e.g. active session) doesn't hit a closed port.
    // Bind separate listeners for IPv4 and IPv6 so the callback works
    // regardless of how the browser resolves `localhost`.
    let v4_addr = std::net::SocketAddr::from(([127, 0, 0, 1], callback_port));
    let v6_addr = std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], callback_port));
    let v4_listener = TcpListener::bind(v4_addr).await?;
    let v6_listener = TcpListener::bind(v6_addr).await.ok(); // IPv6 may not be available
    tracing::info!(port = callback_port, "PKCE callback listener bound");

    // Ask control-plane to build the authorize URL (includes code_challenge)
    let pkce_resp = api.pkce_start(&code_verifier, &redirect_uri).await?;
    let auth_state = pkce_resp.state.clone();

    tracing::info!(url = %pkce_resp.authorize_url, "Opening browser for PKCE auth");

    // Open browser
    if let Err(e) = open::that(&pkce_resp.authorize_url) {
        tracing::warn!(error = %e, "Failed to open browser automatically");
        eprintln!(
            "\nCould not open browser. Please visit:\n  {}\n",
            pkce_resp.authorize_url
        );
    }

    // Wait for the callback on whichever listener receives it first
    let (code, state) = if let Some(v6) = v6_listener {
        tokio::select! {
            result = accept_callback_on(&v4_listener) => result?,
            result = accept_callback_on(&v6) => result?,
        }
    } else {
        accept_callback_on(&v4_listener).await?
    };

    // Verify state matches
    if state != auth_state {
        anyhow::bail!("OAuth state mismatch — possible CSRF attack");
    }

    // Exchange the code for tokens
    let token_resp = api
        .pkce_exchange(&code, &code_verifier, &state, &redirect_uri)
        .await?;

    Ok(token_resp.access_token)
}

/// Accept one HTTP GET request on the given listener, extract
/// `code` and `state` query parameters, respond with a success page.
async fn accept_callback_on(listener: &TcpListener) -> Result<(String, String)> {
    let (mut stream, _addr) = listener.accept().await?;

    // Read the HTTP request (small — just the GET line + headers)
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse the first line: "GET /callback?code=xxx&state=yyy HTTP/1.1"
    let first_line = request.lines().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("");

    let (code, state) = parse_callback_params(path)?;

    // Send back a success response so the browser shows a friendly page
    let body = r#"<!DOCTYPE html>
<html>
<head><title>Login Complete</title></head>
<body style="font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#e0e0e0;">
<div style="text-align:center">
<h1>Authentication Successful</h1>
<p>You can close this tab and return to the terminal.</p>
</div>
</body>
</html>"#;

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;

    Ok((code, state))
}

/// Percent-decode a URL-encoded string (handles %XX sequences and + as space).
fn url_decode(s: &str) -> String {
    let mut result = Vec::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        match b {
            b'%' => {
                let hi = chars.next().unwrap_or(b'0');
                let lo = chars.next().unwrap_or(b'0');
                let hex = [hi, lo];
                if let Ok(s) = std::str::from_utf8(&hex) {
                    if let Ok(byte) = u8::from_str_radix(s, 16) {
                        result.push(byte);
                        continue;
                    }
                }
                result.push(b'%');
                result.push(hi);
                result.push(lo);
            }
            b'+' => result.push(b' '),
            _ => result.push(b),
        }
    }
    String::from_utf8(result).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Parse `code` and `state` from a callback path like `/callback?code=abc&state=def`
fn parse_callback_params(path: &str) -> Result<(String, String)> {
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");

    let mut code = None;
    let mut state = None;

    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            match key {
                "code" => code = Some(url_decode(value)),
                "state" => state = Some(url_decode(value)),
                "error" => {
                    let desc = query.split('&').find_map(|p| {
                        p.split_once('=')
                            .filter(|(k, _)| *k == "error_description")
                            .map(|(_, v)| url_decode(v))
                    });
                    anyhow::bail!(
                        "OIDC provider returned error: {}{}",
                        url_decode(value),
                        desc.map(|d| format!(" — {}", d)).unwrap_or_default()
                    );
                }
                _ => {}
            }
        }
    }

    let code = code.ok_or_else(|| anyhow::anyhow!("Missing 'code' in callback"))?;
    let state = state.ok_or_else(|| anyhow::anyhow!("Missing 'state' in callback"))?;

    Ok((code, state))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── url_decode ──────────────────────────────────────

    #[test]
    fn test_url_decode_plain() {
        assert_eq!(url_decode("hello"), "hello");
    }

    #[test]
    fn test_url_decode_percent() {
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("%3D%26"), "=&");
    }

    #[test]
    fn test_url_decode_plus_as_space() {
        assert_eq!(url_decode("a+b+c"), "a b c");
    }

    #[test]
    fn test_url_decode_mixed() {
        assert_eq!(url_decode("foo%3Dbar+baz"), "foo=bar baz");
    }

    #[test]
    fn test_url_decode_empty() {
        assert_eq!(url_decode(""), "");
    }

    // ── parse_callback_params ───────────────────────────

    #[test]
    fn test_parse_callback_success() {
        let (code, state) = parse_callback_params("/callback?code=abc123&state=xyz789").unwrap();
        assert_eq!(code, "abc123");
        assert_eq!(state, "xyz789");
    }

    #[test]
    fn test_parse_callback_encoded_values() {
        let (code, state) = parse_callback_params("/callback?code=a%20b&state=c%3Dd").unwrap();
        assert_eq!(code, "a b");
        assert_eq!(state, "c=d");
    }

    #[test]
    fn test_parse_callback_missing_code() {
        let result = parse_callback_params("/callback?state=xyz");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("code"));
    }

    #[test]
    fn test_parse_callback_missing_state() {
        let result = parse_callback_params("/callback?code=abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("state"));
    }

    #[test]
    fn test_parse_callback_oidc_error() {
        let result =
            parse_callback_params("/callback?error=access_denied&error_description=User+cancelled");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("access_denied"));
        assert!(msg.contains("User cancelled"));
    }

    #[test]
    fn test_parse_callback_no_query() {
        assert!(parse_callback_params("/callback").is_err());
    }
}
