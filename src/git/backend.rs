use std::path::Path;

use tokio::process::{Child, Command};

use crate::git::mirror::GitError;

// ---------------------------------------------------------------------------
// CGI environment builder
// ---------------------------------------------------------------------------

/// Build the CGI environment for `git http-backend`.
///
/// `tail` is the path suffix after `/<owner>/<repo>.git/`, e.g. `info/refs`
/// or `git-upload-pack`.
///
/// Only the `Some` optional fields are included in the returned vector.
/// `CONTENT_LENGTH` is intentionally omitted here; callers that know the
/// length (e.g. a buffered POST body) should append it themselves.
///
/// `HTTP_CONTENT_ENCODING` deliberately uses the CGI header form rather than
/// `CONTENT_ENCODING`: `git http-backend` uses it to inflate gzip-compressed
/// smart-HTTP request bodies before handing them to `git-upload-pack`.
#[allow(clippy::too_many_arguments)] // CGI env needs all HTTP fields; a struct would be heavier.
pub fn cgi_env(
    storage_path: &Path,
    owner: &str,
    repo: &str,
    tail: &str,
    query: &str,
    method: &str,
    content_type: Option<&str>,
    content_encoding: Option<&str>,
    git_protocol: Option<&str>,
    remote_user: Option<&str>,
) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();

    env.push((
        "GIT_PROJECT_ROOT".to_owned(),
        storage_path.to_string_lossy().into_owned(),
    ));
    env.push(("GIT_HTTP_EXPORT_ALL".to_owned(), "1".to_owned()));
    env.push((
        "PATH_INFO".to_owned(),
        format!("/{owner}/{repo}.git/{tail}"),
    ));
    env.push(("QUERY_STRING".to_owned(), query.to_owned()));
    env.push(("REQUEST_METHOD".to_owned(), method.to_owned()));

    if let Some(ct) = content_type {
        env.push(("CONTENT_TYPE".to_owned(), ct.to_owned()));
    }
    if let Some(encoding) = content_encoding {
        env.push(("HTTP_CONTENT_ENCODING".to_owned(), encoding.to_owned()));
    }
    if let Some(proto) = git_protocol {
        env.push(("GIT_PROTOCOL".to_owned(), proto.to_owned()));
    }
    if let Some(user) = remote_user {
        env.push(("REMOTE_USER".to_owned(), user.to_owned()));
    }

    env
}

// ---------------------------------------------------------------------------
// CGI response head parser
// ---------------------------------------------------------------------------

/// Parse the CGI response head produced by `git http-backend`.
///
/// Returns `Some((status, headers, body_offset))` where:
/// - `status` is the HTTP status code (from a `Status:` line, default 200).
/// - `headers` contains all headers **excluding** the `Status:` line.
/// - `body_offset` is the byte index in `buf` immediately after the blank
///   line that terminates the header block.
///
/// Returns `None` if no blank line (end of headers) is found in `buf`.
///
/// Tolerates both CRLF (`\r\n`) and LF-only (`\n`) line endings.
#[allow(clippy::type_complexity)] // Return type mirrors CGI output structure; a named struct adds little here.
pub fn parse_cgi_head(buf: &[u8]) -> Option<(u16, Vec<(String, String)>, usize)> {
    // Find the blank line that terminates the CGI header block.
    // We look for "\r\n\r\n" or "\n\n" (or a mix like "\r\n\n").
    let body_offset = find_header_end(buf)?;

    let header_block = &buf[..body_offset];

    // Split into lines, tolerating CRLF and LF endings.
    let lines: Vec<&str> = header_block
        .split(|&b| b == b'\n')
        .filter_map(|line| {
            let trimmed = if line.ends_with(b"\r") {
                &line[..line.len() - 1]
            } else {
                line
            };
            std::str::from_utf8(trimmed).ok()
        })
        .collect();

    let mut status: u16 = 200;
    let mut headers: Vec<(String, String)> = Vec::new();

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((key, val)) = line.split_once(':') {
            let key = key.trim();
            let val = val.trim();
            if key.eq_ignore_ascii_case("Status") {
                // Parse the leading integer from "404 Not Found"
                if let Some(code_str) = val.split_whitespace().next()
                    && let Ok(code) = code_str.parse::<u16>()
                {
                    status = code;
                }
                // Status line is excluded from returned headers.
            } else {
                headers.push((key.to_owned(), val.to_owned()));
            }
        }
    }

    Some((status, headers, body_offset))
}

/// Find the byte offset immediately after the blank line ending the CGI
/// header block.  Handles `\r\n\r\n`, `\n\n`, `\r\n\n`, and `\n\r\n`.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    let len = buf.len();
    let mut i = 0;
    while i < len {
        // Advance to the next '\n'.
        if buf[i] != b'\n' {
            i += 1;
            continue;
        }
        // We are at buf[i] == '\n'. The line ended here.
        // Look at what follows to see if it's a blank line.
        let after_nl = i + 1;
        if after_nl >= len {
            i += 1;
            continue;
        }
        if buf[after_nl] == b'\n' {
            // LF-only blank line: "\n\n"
            return Some(after_nl + 1);
        }
        if buf[after_nl] == b'\r' && after_nl + 1 < len && buf[after_nl + 1] == b'\n' {
            // "\n\r\n" — blank line with CRLF after LF terminator
            return Some(after_nl + 2);
        }
        i += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Subprocess spawner
// ---------------------------------------------------------------------------

/// Spawn `git http-backend` with the given CGI environment, with both
/// `stdin` and `stdout` piped (stderr inherits from the parent process).
///
/// The caller is responsible for:
/// - Writing the HTTP request body to `child.stdin` (take it via
///   `child.stdin.take()`).
/// - Reading the CGI response (headers + body) from `child.stdout` (take it
///   via `child.stdout.take()`).
///
/// `git_dir_root` is passed as the working directory for the subprocess;
/// in practice it is the storage root so `GIT_PROJECT_ROOT` resolves
/// correctly even if `git http-backend` tries to `chdir`.
pub async fn spawn(git_dir_root: &Path, env: &[(String, String)]) -> Result<Child, GitError> {
    Command::new("git")
        .arg("http-backend")
        // Clear the inherited environment to avoid leaking secrets that
        // the parent process may hold (e.g. injected credential headers).
        .env_clear()
        .envs(env.iter().cloned())
        .current_dir(git_dir_root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|source| GitError::Spawn {
            path: git_dir_root.to_path_buf(),
            source,
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn env_get<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
        env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    fn env_has_key(env: &[(String, String)], key: &str) -> bool {
        env.iter().any(|(k, _)| k == key)
    }

    // -----------------------------------------------------------------------
    // cgi_env tests
    // -----------------------------------------------------------------------

    #[test]
    fn cgi_env_mandatory_fields() {
        let storage = Path::new("/var/lib/trust/mirrors");
        let env = cgi_env(
            storage,
            "octocat",
            "hello",
            "info/refs",
            "service=git-upload-pack",
            "GET",
            None,
            None,
            None,
            None,
        );

        assert_eq!(
            env_get(&env, "GIT_PROJECT_ROOT"),
            Some("/var/lib/trust/mirrors")
        );
        assert_eq!(env_get(&env, "GIT_HTTP_EXPORT_ALL"), Some("1"));
        assert_eq!(
            env_get(&env, "PATH_INFO"),
            Some("/octocat/hello.git/info/refs")
        );
        assert_eq!(
            env_get(&env, "QUERY_STRING"),
            Some("service=git-upload-pack")
        );
        assert_eq!(env_get(&env, "REQUEST_METHOD"), Some("GET"));
    }

    #[test]
    fn cgi_env_optional_absent_when_none() {
        let env = cgi_env(
            Path::new("/mirrors"),
            "o",
            "r",
            "git-upload-pack",
            "",
            "POST",
            None,
            None,
            None,
            None,
        );

        assert!(!env_has_key(&env, "CONTENT_TYPE"));
        assert!(!env_has_key(&env, "HTTP_CONTENT_ENCODING"));
        assert!(!env_has_key(&env, "GIT_PROTOCOL"));
        assert!(!env_has_key(&env, "REMOTE_USER"));
    }

    #[test]
    fn cgi_env_optional_present_when_some() {
        let env = cgi_env(
            Path::new("/mirrors"),
            "o",
            "r",
            "git-upload-pack",
            "",
            "POST",
            Some("application/x-git-upload-pack-request"),
            Some("gzip"),
            Some("version=2"),
            Some("alice"),
        );

        assert_eq!(
            env_get(&env, "CONTENT_TYPE"),
            Some("application/x-git-upload-pack-request")
        );
        assert_eq!(env_get(&env, "HTTP_CONTENT_ENCODING"), Some("gzip"));
        assert_eq!(env_get(&env, "GIT_PROTOCOL"), Some("version=2"));
        assert_eq!(env_get(&env, "REMOTE_USER"), Some("alice"));
    }

    #[test]
    fn cgi_env_path_info_format() {
        let env = cgi_env(
            Path::new("/s"),
            "myorg",
            "myrepo",
            "git-receive-pack",
            "",
            "POST",
            None,
            None,
            None,
            None,
        );
        assert_eq!(
            env_get(&env, "PATH_INFO"),
            Some("/myorg/myrepo.git/git-receive-pack")
        );
    }

    // -----------------------------------------------------------------------
    // parse_cgi_head tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_status_404_crlf() {
        let buf = b"Status: 404 Not Found\r\nContent-Type: text/plain\r\n\r\nBODY";
        let result = parse_cgi_head(buf);
        assert!(result.is_some());
        let (status, headers, offset) = result.unwrap();

        assert_eq!(status, 404);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Content-Type");
        assert_eq!(headers[0].1, "text/plain");
        assert_eq!(&buf[offset..], b"BODY");
    }

    #[test]
    fn parse_status_200_explicit() {
        let buf =
            b"Status: 200 OK\r\nContent-Type: application/x-git-upload-pack-result\r\n\r\nBODY";
        let (status, headers, offset) = parse_cgi_head(buf).unwrap();

        assert_eq!(status, 200);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Content-Type");
        assert_eq!(headers[0].1, "application/x-git-upload-pack-result");
        assert_eq!(&buf[offset..], b"BODY");
    }

    #[test]
    fn parse_default_status_200_when_no_status_line() {
        let buf = b"Content-Type: application/x-git-upload-pack-advertisement\r\n\r\nDATA";
        let (status, headers, offset) = parse_cgi_head(buf).unwrap();

        assert_eq!(status, 200);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Content-Type");
        assert_eq!(&buf[offset..], b"DATA");
    }

    #[test]
    fn parse_missing_blank_line_returns_none() {
        let buf = b"Status: 200 OK\r\nContent-Type: text/plain";
        assert!(parse_cgi_head(buf).is_none());
    }

    #[test]
    fn parse_lf_only_line_endings() {
        let buf = b"Status: 404 Not Found\nContent-Type: text/plain\n\nBODY";
        let (status, headers, offset) = parse_cgi_head(buf).unwrap();

        assert_eq!(status, 404);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Content-Type");
        assert_eq!(headers[0].1, "text/plain");
        assert_eq!(&buf[offset..], b"BODY");
    }

    #[test]
    fn parse_status_excluded_from_headers() {
        let buf = b"Status: 301 Moved\r\nLocation: /new\r\n\r\n";
        let (status, headers, _offset) = parse_cgi_head(buf).unwrap();

        assert_eq!(status, 301);
        // Status must not appear in headers
        assert!(!headers.iter().any(|(k, _)| k == "Status"));
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Location");
    }

    #[test]
    fn parse_empty_body() {
        let buf = b"Content-Type: text/plain\r\n\r\n";
        let (status, headers, offset) = parse_cgi_head(buf).unwrap();
        assert_eq!(status, 200);
        assert_eq!(headers.len(), 1);
        assert_eq!(offset, buf.len());
    }

    #[test]
    fn parse_multiple_headers() {
        let buf =
            b"Status: 200 OK\r\nContent-Type: text/plain\r\nCache-Control: no-cache\r\n\r\ndata";
        let (status, headers, offset) = parse_cgi_head(buf).unwrap();
        assert_eq!(status, 200);
        assert_eq!(headers.len(), 2);
        assert_eq!(&buf[offset..], b"data");
    }
}
