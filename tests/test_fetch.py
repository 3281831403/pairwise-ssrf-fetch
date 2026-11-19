import time
from urllib.parse import urlsplit

import pytest

from linkpreview.fetch import (
    BlockedURL,
    check_ip,
    fetch,
    fetch_many,
    parse_url,
    validate_redirect,
)

PUBLIC_V4 = "93.184.216.34"


def make_policy(**overrides):
    policy = {
        "schemes": {"http", "https"},
        "allowed_ports": {80, 443},
        "max_redirects": 3,
        "timeout": 1.0,
        "max_bytes": 1024,
        "blocked_networks": ("10.0.0.0/8", "192.168.0.0/16"),
    }
    policy.update(overrides)
    return policy


POLICY = make_policy()


class FixedResolver:
    """Fake DNS that always returns the same public answers."""

    def __init__(self, addresses):
        self.addresses = list(addresses)
        self.calls = []

    def __call__(self, host):
        self.calls.append(host)
        return list(self.addresses)


class SequenceResolver:
    """Fake DNS with scripted answers, one list per query."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, host):
        self.calls.append(host)
        if not self.answers:
            raise AssertionError(f"unexpected DNS query for {host!r}")
        return list(self.answers.pop(0))


class RebindingResolver:
    """First answer public, every later answer internal."""

    def __init__(self):
        self.calls = []

    def __call__(self, host):
        self.calls.append(host)
        if len(self.calls) == 1:
            return [PUBLIC_V4]
        return ["127.0.0.1"]


class FakeOpener:
    """Fake HTTP client with scripted ``(status, headers, body)`` responses."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, timeout):
        self.calls.append((url, timeout))
        if not self.responses:
            raise AssertionError(f"unexpected HTTP request for {url!r}")
        response = self.responses.pop(0)
        if callable(response):
            response = response()
        return response


class ChunkStream:
    """Minimal binary stream that records how many bytes were consumed."""

    def __init__(self, chunks):
        self._chunks = [bytes(chunk) for chunk in chunks]
        self._consumed = 0
        self.closed = False

    def read(self, size=-1):
        if size is None or size < 0:
            size = sum(len(chunk) for chunk in self._chunks)
        out = bytearray()
        while self._chunks and len(out) < size:
            need = size - len(out)
            head = self._chunks[0]
            if len(head) <= need:
                out.extend(head)
                self._chunks.pop(0)
            else:
                out.extend(head[:need])
                self._chunks[0] = head[need:]
        self._consumed += len(out)
        return bytes(out)

    @property
    def consumed(self):
        return self._consumed

    def close(self):
        self.closed = True


class SlowStream:
    """Finite stream whose reads each take longer than the test deadline."""

    def __init__(self, chunks=3, delay=0.05):
        self.remaining = chunks
        self.delay = delay
        self.reads = 0
        self.closed = False

    def read(self, size=-1):
        self.reads += 1
        if self.remaining <= 0:
            return b""
        self.remaining -= 1
        time.sleep(self.delay)
        return b"x"

    def close(self):
        self.closed = True


def test_check_ip_rejects_decimal_encoded_loopback():
    with pytest.raises(BlockedURL):
        check_ip("2130706433", POLICY)


def test_check_ip_rejects_ipv4_mapped_ipv6():
    for address in ("::ffff:127.0.0.1", "::ffff:8.8.8.8"):
        with pytest.raises(BlockedURL):
            check_ip(address, POLICY)


def test_check_ip_rejects_octal_and_hex_encoded_ipv4():
    for address in ("0177.0.0.1", "0x7f.0.0.1", "0x7f000001"):
        with pytest.raises(BlockedURL):
            check_ip(address, POLICY)


def test_dns_rebinding_second_internal_answer_is_rejected():
    resolver = RebindingResolver()
    opener = FakeOpener((200, {}, b"public body"))

    body = fetch("http://rebind.test/", POLICY, resolver, opener)

    assert body == b"public body"
    assert resolver.calls == ["rebind.test"]
    assert urlsplit(opener.calls[0][0]).hostname == PUBLIC_V4


def test_fetch_validates_every_resolved_address_not_just_first():
    resolver = SequenceResolver([[PUBLIC_V4, "127.0.0.1"]])
    opener = FakeOpener((200, {}, b"must not be reached"))

    with pytest.raises(BlockedURL):
        fetch("http://mixed.test/", POLICY, resolver, opener)

    assert opener.calls == []


def test_redirect_to_loopback_is_rejected():
    with pytest.raises(BlockedURL):
        validate_redirect("http://public.test/", "http://127.0.0.1/", POLICY)

    resolver = FixedResolver([PUBLIC_V4])
    opener = FakeOpener((302, {"location": "http://127.0.0.1/"}, b""))

    with pytest.raises(BlockedURL):
        fetch("http://public.test/", POLICY, resolver, opener)

    assert len(opener.calls) == 1


def test_cross_scheme_downgrade_is_rejected():
    with pytest.raises(BlockedURL):
        validate_redirect("https://public.test/", "http://public.test/next", POLICY)

    resolver = FixedResolver([PUBLIC_V4])
    opener = FakeOpener((302, {"location": "http://public.test/next"}, b""))

    with pytest.raises(BlockedURL):
        fetch("https://public.test/", POLICY, resolver, opener)

    assert len(opener.calls) == 1


def test_redirect_over_limit_is_rejected():
    policy = make_policy(max_redirects=2)
    resolver = FixedResolver([PUBLIC_V4])
    opener = FakeOpener(
        (302, {"location": "http://public.test/1"}, b""),
        (302, {"location": "http://public.test/2"}, b""),
        (302, {"location": "http://public.test/3"}, b""),
        (200, {}, b"too late"),
    )

    with pytest.raises(BlockedURL):
        fetch("http://public.test/0", policy, resolver, opener)

    assert len(opener.calls) <= 3


def test_parse_url_rejects_userinfo():
    policy = make_policy(allowed_ports={80, 443, 6379})

    with pytest.raises(BlockedURL):
        parse_url("http://user@127.0.0.1:6379/", policy)


def test_parse_url_rejects_port_outside_allowlist():
    with pytest.raises(BlockedURL):
        parse_url("http://example.com:6379/", POLICY)


def test_parse_url_rejects_non_http_scheme():
    for url in ("ftp://example.com/", "gopher://example.com/"):
        with pytest.raises(BlockedURL):
            parse_url(url, POLICY)


def test_fetch_stops_reading_oversized_stream():
    body = ChunkStream([b"a" * 5, b"b" * 5])
    opener = FakeOpener((200, {}, body))

    with pytest.raises(BlockedURL):
        fetch(
            "http://example.com/",
            POLICY,
            FixedResolver([PUBLIC_V4]),
            opener,
            max_bytes=8,
        )

    assert body.consumed <= 9
    assert body.closed is True


def test_fetch_does_not_trust_lying_content_length():
    body = ChunkStream([b"0123456789"])
    opener = FakeOpener((200, {"Content-Length": "1"}, body))

    with pytest.raises(BlockedURL):
        fetch(
            "http://example.com/",
            POLICY,
            FixedResolver([PUBLIC_V4]),
            opener,
            max_bytes=4,
        )

    assert body.consumed <= 5
    assert body.closed is True


def test_fetch_times_out_on_slow_response():
    body = SlowStream(chunks=3, delay=0.05)
    opener = FakeOpener((200, {}, body))

    with pytest.raises(BlockedURL):
        fetch(
            "http://example.com/",
            make_policy(timeout=0.01),
            FixedResolver([PUBLIC_V4]),
            opener,
        )

    assert body.reads >= 1
    assert body.closed is True


def test_normal_url_returns_body_through_fake_opener():
    resolver = FixedResolver([PUBLIC_V4])
    opener = FakeOpener(
        (200, {"Content-Type": "text/plain"}, b"one"),
        (200, {}, b"two"),
        (200, {}, b"three"),
    )

    assert fetch("http://example.com/one", POLICY, resolver, opener) == b"one"
    assert fetch_many(
        ["http://example.com/two", "https://example.com/three"],
        POLICY,
        resolver,
        opener,
    ) == [b"two", b"three"]

    assert len(resolver.calls) == 3
    assert all(0 < timeout <= POLICY["timeout"] for _, timeout in opener.calls)
