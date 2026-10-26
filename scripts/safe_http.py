"""HTTP helpers that never follow redirects implicitly."""
import urllib.error
import urllib.request


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return redirect responses to the caller instead of following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def safe_open(request, timeout=10):
    """Open one URL and return 3xx responses for explicit caller validation."""
    opener = urllib.request.build_opener(NoRedirectHandler())
    try:
        return opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as response:
        if 300 <= response.code < 400:
            return response
        raise
