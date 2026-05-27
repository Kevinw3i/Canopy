use crate::api_client::ApiClient;
use anyhow::{Context, Result};
use shared::dto::auth::{
    WebAuthnRegisterFinishRequest, WebAuthnRegisterFinishResponse, WebAuthnRegisterStartRequest,
    WebAuthnRegisterStartResponse, WebAuthnVerifyFinishRequest, WebAuthnVerifyResponse,
    WebAuthnVerifyStartRequest, WebAuthnVerifyStartResponse,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_WEBAUTHN_REQUEST_BYTES: usize = 128 * 1024;

struct LocalhostListeners {
    v4: TcpListener,
    v6: Option<TcpListener>,
    port: u16,
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

enum RegistrationServerEvent {
    Continue,
    Finished(WebAuthnRegisterFinishResponse),
}

enum VerificationServerEvent {
    Continue,
    Finished(WebAuthnVerifyResponse),
}

pub async fn start_webauthn_registration_flow(
    api: &ApiClient,
) -> Result<WebAuthnRegisterFinishResponse> {
    let listeners = LocalhostListeners::bind_ephemeral().await?;
    let origin = listeners.origin();
    let started = api
        .start_webauthn_registration(&WebAuthnRegisterStartRequest {
            origin: origin.clone(),
            label: Some("Security key".into()),
        })
        .await?;
    let url = format!("{origin}/");

    tracing::info!(url = %url, "Opening browser for WebAuthn registration");
    if let Err(err) = open::that(&url) {
        tracing::warn!(error = %err, "Failed to open browser automatically");
        eprintln!("\nCould not open browser. Please visit:\n  {}\n", url);
    }

    serve_registration_until_finished(listeners, api, started).await
}

pub async fn start_webauthn_verification_flow(api: &ApiClient) -> Result<WebAuthnVerifyResponse> {
    let listeners = LocalhostListeners::bind_ephemeral().await?;
    let origin = listeners.origin();
    let started = api
        .start_webauthn_verification(&WebAuthnVerifyStartRequest {
            origin: origin.clone(),
        })
        .await?;
    let url = format!("{origin}/");

    tracing::info!(url = %url, "Opening browser for WebAuthn verification");
    if let Err(err) = open::that(&url) {
        tracing::warn!(error = %err, "Failed to open browser automatically");
        eprintln!("\nCould not open browser. Please visit:\n  {}\n", url);
    }

    serve_verification_until_finished(listeners, api, started).await
}

impl LocalhostListeners {
    async fn bind_ephemeral() -> Result<Self> {
        let v4 = TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let port = v4.local_addr()?.port();
        let v6_addr = std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port));
        let v6 = TcpListener::bind(v6_addr).await.ok();
        Ok(Self { v4, v6, port })
    }

    fn origin(&self) -> String {
        format!("http://localhost:{}", self.port)
    }
}

async fn serve_registration_until_finished(
    listeners: LocalhostListeners,
    api: &ApiClient,
    started: WebAuthnRegisterStartResponse,
) -> Result<WebAuthnRegisterFinishResponse> {
    let page = registration_page(&started.public_key)?;
    loop {
        let stream = accept_next(&listeners).await?;
        match handle_registration_request(stream, api, &started, &page).await? {
            RegistrationServerEvent::Continue => {}
            RegistrationServerEvent::Finished(response) => return Ok(response),
        }
    }
}

async fn serve_verification_until_finished(
    listeners: LocalhostListeners,
    api: &ApiClient,
    started: WebAuthnVerifyStartResponse,
) -> Result<WebAuthnVerifyResponse> {
    let page = verification_page(&started.public_key)?;
    loop {
        let stream = accept_next(&listeners).await?;
        match handle_verification_request(stream, api, &started, &page).await? {
            VerificationServerEvent::Continue => {}
            VerificationServerEvent::Finished(response) => return Ok(response),
        }
    }
}

async fn accept_next(listeners: &LocalhostListeners) -> Result<TcpStream> {
    if let Some(v6) = &listeners.v6 {
        let (stream, _) = tokio::select! {
            accepted = listeners.v4.accept() => accepted?,
            accepted = v6.accept() => accepted?,
        };
        Ok(stream)
    } else {
        let (stream, _) = listeners.v4.accept().await?;
        Ok(stream)
    }
}

async fn handle_registration_request(
    mut stream: TcpStream,
    api: &ApiClient,
    started: &WebAuthnRegisterStartResponse,
    page: &str,
) -> Result<RegistrationServerEvent> {
    let request = read_http_request(&mut stream).await?;
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => {
            write_response(&mut stream, "200 OK", "text/html; charset=utf-8", page).await?;
            Ok(RegistrationServerEvent::Continue)
        }
        ("GET", "/favicon.ico") => {
            write_empty_response(&mut stream, "204 No Content").await?;
            Ok(RegistrationServerEvent::Continue)
        }
        ("POST", "/finish") => {
            let credential: serde_json::Value = serde_json::from_slice(&request.body)
                .context("WebAuthn browser response was invalid JSON")?;
            let request = WebAuthnRegisterFinishRequest {
                factor_id: started.factor_id.clone(),
                credential,
            };
            match api.finish_webauthn_registration(&request).await {
                Ok(response) => {
                    let body = serde_json::json!({
                        "ok": true,
                        "credential_id": response.credential_id,
                    });
                    write_response(
                        &mut stream,
                        "200 OK",
                        "application/json; charset=utf-8",
                        &body.to_string(),
                    )
                    .await?;
                    Ok(RegistrationServerEvent::Finished(response))
                }
                Err(err) => {
                    let message = err.to_string();
                    let body = serde_json::json!({
                        "ok": false,
                        "error": message,
                    });
                    write_response(
                        &mut stream,
                        "400 Bad Request",
                        "application/json; charset=utf-8",
                        &body.to_string(),
                    )
                    .await?;
                    anyhow::bail!(message)
                }
            }
        }
        _ => {
            write_response(
                &mut stream,
                "404 Not Found",
                "text/plain; charset=utf-8",
                "Not found",
            )
            .await?;
            Ok(RegistrationServerEvent::Continue)
        }
    }
}

async fn handle_verification_request(
    mut stream: TcpStream,
    api: &ApiClient,
    started: &WebAuthnVerifyStartResponse,
    page: &str,
) -> Result<VerificationServerEvent> {
    let request = read_http_request(&mut stream).await?;
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => {
            write_response(&mut stream, "200 OK", "text/html; charset=utf-8", page).await?;
            Ok(VerificationServerEvent::Continue)
        }
        ("GET", "/favicon.ico") => {
            write_empty_response(&mut stream, "204 No Content").await?;
            Ok(VerificationServerEvent::Continue)
        }
        ("POST", "/finish") => {
            let credential: serde_json::Value = serde_json::from_slice(&request.body)
                .context("WebAuthn browser response was invalid JSON")?;
            let request = WebAuthnVerifyFinishRequest {
                challenge_id: started.challenge_id.clone(),
                credential,
            };
            match api.finish_webauthn_verification(&request).await {
                Ok(response) => {
                    let body = serde_json::json!({
                        "ok": true,
                        "credential_id": response.credential_id,
                    });
                    write_response(
                        &mut stream,
                        "200 OK",
                        "application/json; charset=utf-8",
                        &body.to_string(),
                    )
                    .await?;
                    Ok(VerificationServerEvent::Finished(response))
                }
                Err(err) => {
                    let message = err.to_string();
                    let body = serde_json::json!({
                        "ok": false,
                        "error": message,
                    });
                    write_response(
                        &mut stream,
                        "400 Bad Request",
                        "application/json; charset=utf-8",
                        &body.to_string(),
                    )
                    .await?;
                    anyhow::bail!(message)
                }
            }
        }
        _ => {
            write_response(
                &mut stream,
                "404 Not Found",
                "text/plain; charset=utf-8",
                "Not found",
            )
            .await?;
            Ok(VerificationServerEvent::Continue)
        }
    }
}

async fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut buf = Vec::new();
    let mut temp = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            anyhow::bail!("WebAuthn browser connection closed before request headers");
        }
        buf.extend_from_slice(&temp[..n]);
        if buf.len() > MAX_WEBAUTHN_REQUEST_BYTES {
            anyhow::bail!("WebAuthn browser request exceeded size limit");
        }
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
    };

    let headers_end = header_end + 4;
    let headers = String::from_utf8_lossy(&buf[..headers_end]);
    let first_line = headers.lines().next().unwrap_or("");
    let (method, path) = parse_request_line(first_line)?;
    let content_length = parse_content_length(&headers).unwrap_or(0);
    if headers_end + content_length > MAX_WEBAUTHN_REQUEST_BYTES {
        anyhow::bail!("WebAuthn browser request exceeded size limit");
    }
    while buf.len() < headers_end + content_length {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            anyhow::bail!("WebAuthn browser connection closed before body completed");
        }
        buf.extend_from_slice(&temp[..n]);
        if buf.len() > MAX_WEBAUTHN_REQUEST_BYTES {
            anyhow::bail!("WebAuthn browser request exceeded size limit");
        }
    }

    Ok(HttpRequest {
        method,
        path,
        body: buf[headers_end..headers_end + content_length].to_vec(),
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_request_line(line: &str) -> Result<(String, String)> {
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing HTTP method"))?;
    let raw_path = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing HTTP path"))?;
    let path = raw_path.split_once('?').map_or(raw_path, |(path, _)| path);
    Ok((method.to_string(), path.to_string()))
}

fn parse_content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn write_empty_response(stream: &mut TcpStream, status: &str) -> Result<()> {
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

fn registration_page(public_key: &serde_json::Value) -> Result<String> {
    let public_key_json = serde_json::to_string(public_key)?.replace("</", "<\\/");
    Ok(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Canopy Passkey Setup</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #101827;
      color: #e5eefb;
      font: 15px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{
      width: min(520px, calc(100vw - 32px));
      border: 1px solid #334155;
      background: #111f33;
      padding: 28px;
      box-sizing: border-box;
    }}
    h1 {{ margin: 0 0 10px; font-size: 22px; line-height: 1.2; }}
    p {{ margin: 0 0 20px; color: #b7c4d6; }}
    button {{
      appearance: none;
      border: 0;
      background: #7dd3fc;
      color: #082f49;
      font-weight: 700;
      padding: 10px 14px;
      cursor: pointer;
    }}
    button:disabled {{ cursor: wait; opacity: .68; }}
    #status {{ margin-top: 18px; color: #b7c4d6; white-space: pre-wrap; }}
    .ok {{ color: #86efac; }}
    .err {{ color: #fca5a5; }}
  </style>
</head>
<body>
  <main>
    <h1>Canopy Passkey Setup</h1>
    <p>Create a local passkey for this Canopy account. Keep this tab open until the terminal reports completion.</p>
    <button id="start" type="button">Create passkey</button>
    <div id="status">Waiting for browser gesture.</div>
  </main>
  <script>
    const publicKey = {public_key_json};
    const statusEl = document.getElementById("status");
    const button = document.getElementById("start");

    function b64urlEncode(buf) {{
      let s = btoa(String.fromCharCode(...new Uint8Array(buf)));
      return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }}
    function b64urlDecode(str) {{
      str = str.replace(/-/g, "+").replace(/_/g, "/");
      while (str.length % 4) str += "=";
      const bin = atob(str);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out.buffer;
    }}
    function setStatus(text, cls) {{
      statusEl.textContent = text;
      statusEl.className = cls || "";
    }}
    function credentialOptions() {{
      const opts = JSON.parse(JSON.stringify(publicKey));
      opts.challenge = b64urlDecode(opts.challenge);
      opts.user.id = b64urlDecode(opts.user.id);
      if (opts.excludeCredentials) {{
        opts.excludeCredentials = opts.excludeCredentials.map((item) => ({{
          ...item,
          id: b64urlDecode(item.id),
        }}));
      }}
      return opts;
    }}

    button.addEventListener("click", async () => {{
      button.disabled = true;
      try {{
        setStatus("Waiting for authenticator...");
        const cred = await navigator.credentials.create({{ publicKey: credentialOptions() }});
        const body = {{
          id: cred.id,
          attestationObject: b64urlEncode(cred.response.attestationObject),
          clientDataJSON: b64urlEncode(cred.response.clientDataJSON),
          transports: cred.response.getTransports ? cred.response.getTransports() : [],
        }};
        setStatus("Saving passkey in Canopy...");
        const resp = await fetch("/finish", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify(body),
        }});
        const result = await resp.json();
        if (!resp.ok || !result.ok) throw new Error(result.error || "Passkey registration failed");
        setStatus("Passkey enrolled. You can close this tab and return to the terminal.", "ok");
      }} catch (err) {{
        button.disabled = false;
        setStatus(err && err.message ? err.message : String(err), "err");
      }}
    }});
  </script>
</body>
</html>"#
    ))
}

fn verification_page(public_key: &serde_json::Value) -> Result<String> {
    let public_key_json = serde_json::to_string(public_key)?.replace("</", "<\\/");
    Ok(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Canopy Passkey Verification</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #101827;
      color: #e5eefb;
      font: 15px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{
      width: min(520px, calc(100vw - 32px));
      border: 1px solid #334155;
      background: #111f33;
      padding: 28px;
      box-sizing: border-box;
    }}
    h1 {{ margin: 0 0 10px; font-size: 22px; line-height: 1.2; }}
    p {{ margin: 0 0 20px; color: #b7c4d6; }}
    button {{
      appearance: none;
      border: 0;
      background: #7dd3fc;
      color: #082f49;
      font-weight: 700;
      padding: 10px 14px;
      cursor: pointer;
    }}
    button:disabled {{ cursor: wait; opacity: .68; }}
    #status {{ margin-top: 18px; color: #b7c4d6; white-space: pre-wrap; }}
    .ok {{ color: #86efac; }}
    .err {{ color: #fca5a5; }}
  </style>
</head>
<body>
  <main>
    <h1>Canopy Passkey Verification</h1>
    <p>Verify your local passkey for this Canopy session. Keep this tab open until the terminal reports completion.</p>
    <button id="start" type="button">Verify passkey</button>
    <div id="status">Waiting for browser gesture.</div>
  </main>
  <script>
    const publicKey = {public_key_json};
    const statusEl = document.getElementById("status");
    const button = document.getElementById("start");

    function b64urlEncode(buf) {{
      let s = btoa(String.fromCharCode(...new Uint8Array(buf)));
      return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }}
    function b64urlDecode(str) {{
      str = str.replace(/-/g, "+").replace(/_/g, "/");
      while (str.length % 4) str += "=";
      const bin = atob(str);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out.buffer;
    }}
    function setStatus(text, cls) {{
      statusEl.textContent = text;
      statusEl.className = cls || "";
    }}
    function credentialOptions() {{
      const opts = JSON.parse(JSON.stringify(publicKey));
      opts.challenge = b64urlDecode(opts.challenge);
      if (opts.allowCredentials) {{
        opts.allowCredentials = opts.allowCredentials.map((item) => ({{
          ...item,
          id: b64urlDecode(item.id),
        }}));
      }}
      return opts;
    }}

    button.addEventListener("click", async () => {{
      button.disabled = true;
      try {{
        setStatus("Waiting for authenticator...");
        const cred = await navigator.credentials.get({{ publicKey: credentialOptions() }});
        const body = {{
          id: cred.id,
          authenticatorData: b64urlEncode(cred.response.authenticatorData),
          signature: b64urlEncode(cred.response.signature),
          clientDataJSON: b64urlEncode(cred.response.clientDataJSON),
        }};
        if (cred.response.userHandle) {{
          body.userHandle = b64urlEncode(cred.response.userHandle);
        }}
        setStatus("Saving verification in Canopy...");
        const resp = await fetch("/finish", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify(body),
        }});
        const result = await resp.json();
        if (!resp.ok || !result.ok) throw new Error(result.error || "Passkey verification failed");
        setStatus("Passkey verified. You can close this tab and return to the terminal.", "ok");
      }} catch (err) {{
        button.disabled = false;
        setStatus(err && err.message ? err.message : String(err), "err");
      }}
    }});
  </script>
</body>
</html>"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_http_request_line_and_query() {
        let (method, path) = parse_request_line("POST /finish?unused=1 HTTP/1.1").unwrap();
        assert_eq!(method, "POST");
        assert_eq!(path, "/finish");
    }

    #[test]
    fn parses_content_length_case_insensitive() {
        let headers = "POST /finish HTTP/1.1\r\nhost: localhost\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(parse_content_length(headers), Some(42));
    }

    #[test]
    fn registration_page_embeds_options_and_finish_endpoint() {
        let html = registration_page(&json!({
            "challenge": "abc",
            "user": {"id": "def", "name": "alice"},
            "rp": {"id": "localhost", "name": "Canopy"}
        }))
        .unwrap();
        assert!(html.contains("Canopy Passkey Setup"));
        assert!(html.contains("navigator.credentials.create"));
        assert!(html.contains("fetch(\"/finish\""));
        assert!(html.contains("\"challenge\":\"abc\""));
    }

    #[test]
    fn verification_page_embeds_options_and_finish_endpoint() {
        let html = verification_page(&json!({
            "challenge": "abc",
            "rpId": "localhost",
            "allowCredentials": [{"type": "public-key", "id": "credential-1"}]
        }))
        .unwrap();
        assert!(html.contains("Canopy Passkey Verification"));
        assert!(html.contains("navigator.credentials.get"));
        assert!(html.contains("fetch(\"/finish\""));
        assert!(html.contains("\"allowCredentials\""));
        assert!(html.contains("authenticatorData"));
    }
}
