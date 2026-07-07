//! HTTP request classification for git smart-HTTP protocol.

#[derive(Debug, PartialEq, Eq)]
pub enum GitRequest {
    Read,
    Push,
    Other,
}

/// Classify a git smart-HTTP request.
///
/// - **Read**: `GET .../info/refs?service=git-upload-pack` or `POST .../git-upload-pack`
/// - **Push**: `GET .../info/refs?service=git-receive-pack` or `POST .../git-receive-pack`
/// - **Other**: anything else
pub fn classify(method: &str, path: &str, query: &str) -> GitRequest {
    let service = parse_service(query);

    if method == "GET" && path.ends_with("/info/refs") {
        return match service {
            Some("git-upload-pack") => GitRequest::Read,
            Some("git-receive-pack") => GitRequest::Push,
            _ => GitRequest::Other,
        };
    }

    if method == "POST" {
        if path.ends_with("/git-upload-pack") {
            return GitRequest::Read;
        }
        if path.ends_with("/git-receive-pack") {
            return GitRequest::Push;
        }
    }

    GitRequest::Other
}

/// Extract the value of the `service` query parameter, if present.
fn parse_service(query: &str) -> Option<&str> {
    for part in query.split('&') {
        if let Some(val) = part.strip_prefix("service=") {
            return Some(val);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_info_refs_upload_pack_is_read() {
        assert_eq!(
            classify("GET", "/o/r.git/info/refs", "service=git-upload-pack"),
            GitRequest::Read
        );
    }

    #[test]
    fn post_git_upload_pack_is_read() {
        assert_eq!(
            classify("POST", "/o/r.git/git-upload-pack", ""),
            GitRequest::Read
        );
    }

    #[test]
    fn get_info_refs_receive_pack_is_push() {
        assert_eq!(
            classify("GET", "/o/r.git/info/refs", "service=git-receive-pack"),
            GitRequest::Push
        );
    }

    #[test]
    fn post_git_receive_pack_is_push() {
        assert_eq!(
            classify("POST", "/o/r.git/git-receive-pack", ""),
            GitRequest::Push
        );
    }

    #[test]
    fn get_info_refs_no_service_is_other() {
        assert_eq!(classify("GET", "/o/r.git/info/refs", ""), GitRequest::Other);
    }

    #[test]
    fn get_info_refs_unknown_service_is_other() {
        assert_eq!(
            classify("GET", "/o/r.git/info/refs", "service=git-unknown"),
            GitRequest::Other
        );
    }

    #[test]
    fn get_head_is_other() {
        assert_eq!(classify("GET", "/o/r.git/HEAD", ""), GitRequest::Other);
    }

    #[test]
    fn service_param_with_extra_params() {
        // service= may appear alongside other query params
        assert_eq!(
            classify(
                "GET",
                "/o/r.git/info/refs",
                "foo=bar&service=git-upload-pack&baz=1"
            ),
            GitRequest::Read
        );
    }
}
