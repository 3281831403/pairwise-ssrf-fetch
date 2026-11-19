"""Injectable URL fetching for the link preview service.

This module intentionally contains only the contracts and stubs.  All I/O is
injected: ``resolver`` performs DNS resolution and ``opener`` performs the HTTP
request, so tests can use fakes and never touch the network.

Canonical policy keys (all optional, defaults shown)::

    {
        "schemes": {"http", "https"},
        "allowed_ports": {80, 443},
        "max_redirects": 5,
        "timeout": 5.0,
        "max_bytes": 1048576,
        "blocked_networks": (),
        "redirects_followed": 0,
    }
"""

import ipaddress
import time
from urllib.parse import urlsplit

_DEFAULT_SCHEMES = {"http", "https"}
_DEFAULT_PORTS = {80, 443}
_DEFAULT_MAX_REDIRECTS = 5
_DEFAULT_TIMEOUT = 5.0
_DEFAULT_MAX_BYTES = 1048576

_DEFAULT_PORT_BY_SCHEME = {"http": 80, "https": 443}


class BlockedURL(Exception):
    """Raised when a URL, address, redirect, response, or deadline is unsafe."""


def parse_url(url: str, policy: dict) -> dict:
    """Parse and normalize one URL according to ``policy``.

    Contract:
      * ``urlsplit`` is the only parser.  The URL must be an absolute URL with
        a scheme and a host.
      * Scheme must be in ``policy["schemes"]`` (default ``{"http", "https"}``).
      * Userinfo is forbidden.  A URL whose username or password component is
        present, including ``http://user@host/``, raises ``BlockedURL``.
      * The host is lowercased.  Non-ASCII hosts are converted with the IDNA
        codec and returned in ASCII form; IPv6 literals stay as IP literals.
        An empty host or an unparseable host raises ``BlockedURL``.
      * The port defaults to 80 for http and 443 for https.  An explicit or
        defaulted port must belong to ``policy["allowed_ports"]`` (default
        ``{80, 443}``); otherwise raise ``BlockedURL``.
      * The path is preserved exactly as returned by ``urlsplit`` (no
        normalization, no percent-decoding) and the query is returned without
        its leading ``?``.

    Returns a new dict with exactly these keys::

        {"scheme": str, "host": str, "port": int, "path": str, "query": str}

    Raises ``BlockedURL`` for every policy violation or malformed URL.
    """

    schemes = policy.get("schemes", _DEFAULT_SCHEMES)
    allowed_ports = policy.get("allowed_ports", _DEFAULT_PORTS)

    try:
        parts = urlsplit(url)
    except (ValueError, TypeError) as exc:
        raise BlockedURL(f"malformed URL: {url!r}") from exc

    scheme = parts.scheme.lower()
    if not scheme or scheme not in schemes:
        raise BlockedURL(f"scheme not allowed: {parts.scheme!r}")

    try:
        if parts.username is not None or parts.password is not None:
            raise BlockedURL("userinfo is not allowed")
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise BlockedURL(f"malformed URL: {url!r}") from exc

    if not host:
        raise BlockedURL("missing host")

    host = host.lower()
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        try:
            host = host.encode("idna").decode("ascii")
        except (UnicodeError, ValueError) as exc:
            raise BlockedURL(f"unparseable host: {host!r}") from exc
    if not host:
        raise BlockedURL("missing host")

    if port is None:
        port = _DEFAULT_PORT_BY_SCHEME.get(scheme)
        if port is None:
            raise BlockedURL(f"no default port for scheme {scheme!r}")
    if port not in allowed_ports:
        raise BlockedURL(f"port not allowed: {port}")

    return {
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": parts.path,
        "query": parts.query,
    }


def check_ip(ip: str, policy: dict) -> None:
    """Validate one already-resolved IP address; return ``None`` on success.

    Contract:
      * Only canonical textual addresses accepted by ``ipaddress.ip_address``
        are allowed.  Non-canonical IPv4 spellings (decimal integer such as
        ``2130706433``, octal ``0177.0.0.1``, hexadecimal ``0x7f.0.0.1``, and
        shortened forms) must raise ``BlockedURL``; do not use
        ``socket.inet_aton`` because it would accept them.
      * An IPv4-mapped IPv6 address (for example ``::ffff:127.0.0.1``) is
        always rejected, regardless of the mapped address.
      * Reject loopback, private, link-local, multicast, reserved, and
        unspecified addresses.  Also reject any address inside a network in
        ``policy["blocked_networks"]``; each item may be an
        ``ipaddress`` network object or a CIDR string.
      * This function does not resolve names and performs no I/O.  A malformed
        address raises ``BlockedURL``.
    """

    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise BlockedURL(f"non-canonical or malformed IP address: {ip!r}") from exc

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        raise BlockedURL(f"IPv4-mapped IPv6 address is not allowed: {ip!r}")

    if (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise BlockedURL(f"address is not a public unicast address: {ip!r}")

    for network in policy.get("blocked_networks", ()):
        if isinstance(network, str):
            network = ipaddress.ip_network(network, strict=False)
        if address in network:
            raise BlockedURL(f"address is inside a blocked network: {ip!r}")


def validate_redirect(from_url: str, to_url: str, policy: dict) -> None:
    """Validate one manually followed redirect hop.

    Contract:
      * Re-parse both URLs with :func:`parse_url`; never trust the previous
        hop's parse result or the ``Location`` string.
      * ``https`` to ``http`` is a downgrade and raises ``BlockedURL``.  An
        ``http`` to ``https`` upgrade is allowed.  Any other scheme change is
        rejected.
      * If the target host is an IP literal, pass it through :func:`check_ip`
        before returning; otherwise resolution and validation of every
        returned address is the caller's immediate next step (``fetch`` does
        this for every hop before opening a connection).
      * ``policy["max_redirects"]`` is the maximum number of redirects that
        may be followed (default 5).  ``policy["redirects_followed"]`` is the
        count already followed before this hop (default 0).  If that count is
        greater than or equal to the maximum, raise ``BlockedURL``.

    Returns ``None`` when the hop may be followed.  This function performs no
    I/O; DNS for a hostname target is resolved and checked by ``fetch`` after
    this function succeeds.
    """

    max_redirects = policy.get("max_redirects", _DEFAULT_MAX_REDIRECTS)
    redirects_followed = policy.get("redirects_followed", 0)
    if redirects_followed >= max_redirects:
        raise BlockedURL("redirect limit exceeded")

    source = parse_url(from_url, policy)
    target = parse_url(to_url, policy)

    if source["scheme"] != target["scheme"]:
        if source["scheme"] == "http" and target["scheme"] == "https":
            pass  # upgrade is allowed
        else:
            raise BlockedURL(
                f"scheme change not allowed: {source['scheme']} -> {target['scheme']}"
            )

    try:
        ipaddress.ip_address(target["host"])
    except ValueError:
        return  # hostname target: caller resolves and validates next
    check_ip(target["host"], policy)


def _header_get(headers, name):
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def _read_body(body, max_bytes, deadline):
    """Read ``body`` enforcing the byte cap and the deadline while reading."""
    if isinstance(body, (bytes, bytearray)):
        data = bytes(body)
        if len(data) > max_bytes:
            raise BlockedURL("response body exceeds byte limit")
        return data

    chunks = []
    total = 0
    try:
        while True:
            if time.monotonic() > deadline:
                raise BlockedURL("deadline exhausted while reading body")
            chunk = body.read(min(65536, max_bytes - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise BlockedURL("response body exceeds byte limit")
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    return b"".join(chunks)


def fetch(
    url: str,
    policy: dict,
    resolver,
    opener,
    max_bytes: int = 1048576,
) -> bytes:
    """Fetch one URL with SSRF-safe validation, manual redirects, and limits.

    ``resolver(host) -> list[str]`` is the only DNS mechanism.  ``opener(
    url, timeout) -> (status, headers, body)`` is the only HTTP mechanism.
    Neither function may perform hidden name resolution; this function must
    never pass a hostname to ``opener``.

    Contract:
      * For the initial URL and for every redirect target: call
        :func:`parse_url`, resolve the host exactly once with ``resolver``,
        require a non-empty answer, and call :func:`check_ip` on *every*
        returned A/AAAA address.  Reject the request if any address is unsafe.
        Choose one validated address for the connection; do not resolve again.
      * Open a URL whose host component is the chosen validated IP literal
        (bracket IPv6), preserving scheme, port, path, and query.  This pins
        the connection and prevents DNS rebinding.  ``opener`` receives the
        remaining total timeout.
      * Never follow redirects automatically.  A 2xx response yields its body;
        a 3xx response requires ``Location``, is passed through
        :func:`validate_redirect`, is counted against
        ``policy["max_redirects"]``, and is then re-parsed, re-resolved, and
        checked as a new hop.  A missing/invalid ``Location``, an over-limit
        redirect count, or any other status raises ``BlockedURL``.
      * ``max_bytes`` is the actual number of body bytes allowed (default
        1048576).  Read incrementally and enforce the limit while reading; do
        not trust ``Content-Length``.  If reading would produce more than
        ``max_bytes`` bytes, close the body immediately and raise
        ``BlockedURL``.  The returned value is ``bytes`` of length at most
        ``max_bytes``.
      * ``policy["timeout"]`` (default 5.0 seconds) is a total deadline for the
        complete operation, covering resolution, opening, redirect hops, and
        body reads.  Use ``time.monotonic`` and pass only the remaining time
        to ``opener``.  When the deadline is exhausted, close any body and
        raise ``BlockedURL``.
      * ``headers`` is a case-insensitive mapping (keys may be lowercased).
        ``body`` is either ``bytes`` or a binary stream with ``read(size)``.
        Close the body when it exposes ``close()``.
      * This function performs no DNS or sockets of its own; all network work
        goes through the injected callables.

    Returns the response body as ``bytes``.  Raises ``BlockedURL`` for any
    policy, resolution, redirect, size, or deadline violation.
    """

    timeout = policy.get("timeout", _DEFAULT_TIMEOUT)
    deadline = time.monotonic() + timeout

    current_url = url
    redirects_followed = 0

    while True:
        parsed = parse_url(current_url, policy)

        addresses = resolver(parsed["host"])
        if not addresses:
            raise BlockedURL(f"empty DNS answer for {parsed['host']!r}")
        for address in addresses:
            check_ip(address, policy)
        chosen = addresses[0]

        host_literal = f"[{chosen}]" if ":" in chosen else chosen
        pinned_url = f"{parsed['scheme']}://{host_literal}:{parsed['port']}{parsed['path']}"
        if parsed["query"]:
            pinned_url += f"?{parsed['query']}"

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BlockedURL("deadline exhausted before opening connection")

        status, headers, body = opener(pinned_url, remaining)

        if 200 <= status < 300:
            return _read_body(body, max_bytes, deadline)

        close = getattr(body, "close", None)
        if callable(close):
            close()

        if 300 <= status < 400:
            location = _header_get(headers, "location")
            if not location:
                raise BlockedURL("redirect without Location header")
            hop_policy = dict(policy)
            hop_policy["redirects_followed"] = redirects_followed
            validate_redirect(current_url, location, hop_policy)
            redirects_followed += 1
            current_url = location
            continue

        raise BlockedURL(f"unexpected response status: {status}")


def fetch_many(
    urls: list[str],
    policy: dict,
    resolver,
    opener,
) -> list[bytes]:
    """Fetch a batch of URLs with exactly the same validation as ``fetch``.

    Contract:
      * Process URLs in order.  Each URL is fetched through :func:`fetch` with
        the same ``policy``, ``resolver``, and ``opener``; do not cache DNS
        answers, connection results, or a previous validation decision between
        URLs.
      * Use ``policy["max_bytes"]`` if present (default 1048576) as the
        per-URL byte cap.
      * Return a list of ``bytes`` in the same order as ``urls``.  Stop and
        propagate ``BlockedURL`` on the first blocked URL; do not return a
        partially validated result.
      * No network I/O except through the injected callables.
    """

    max_bytes = policy.get("max_bytes", _DEFAULT_MAX_BYTES)
    results = []
    for url in urls:
        results.append(fetch(url, policy, resolver, opener, max_bytes=max_bytes))
    return results
