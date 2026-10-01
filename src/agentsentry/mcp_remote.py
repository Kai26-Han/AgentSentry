"""固定远程 MCP 出口。凭据和地址只来自可信配置，模型不能提供。"""

import asyncio
import base64
import hashlib
import ipaddress
import json
import re
import socket
import ssl
from pathlib import Path
from urllib.parse import urlsplit

import httpx2
from httpcore2._backends.anyio import AnyIOBackend
from httpcore2._backends.sync import SyncBackend
import jwt
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from .config import get_settings
from .database import tenant_schema
from .mcp_supply import (active_profile, config_hash, manifest_snapshot, record_candidate,
                         record_incident, seed_baseline, snapshot_hash)


PROTOCOL = "streamable-http"
ENDPOINT_ID = "remote-demo"
UPSTREAM = {
    "remote_mcp_lookup_card": ("lookup_card", "cards.read", {"card_id"}),
    "remote_mcp_record_note": ("record_note", "notes.write", {"note_id", "text", "operation_id"}),
}
CANARY_CARD = "remote-public-guide"
CANARY_CONTENT_SHA256 = hashlib.sha256(
    b"Synthetic remote quarterly guide. Review the plan before Friday.").hexdigest()
_ID = re.compile(r"[a-zA-Z0-9_-]{1,80}\Z")


def _safe_https(url: str) -> str:
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment or parsed.query or len(url) > 500):
        raise ValueError("Remote MCP URL must be a fixed HTTPS endpoint")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", parsed.hostname):
            raise ValueError("Invalid remote MCP hostname") from None
    else:
        raise ValueError("Remote MCP IP literals are not permitted")
    return url


def _validate_network(url: str) -> list[str]:
    """Resolve once; callers must connect to an IP from this returned set."""
    parsed = urlsplit(_safe_https(url))
    addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    ips = [ipaddress.ip_address(item[4][0]) for item in addresses]
    demo = get_settings().agentsentry_remote_mcp_allow_loopback_demo
    if demo and parsed.hostname == "localhost" and ips and all(ip.is_loopback for ip in ips):
        return [str(ip) for ip in sorted(set(ips), key=lambda ip: (ip.version != 4, int(ip)))]
    if demo and parsed.hostname == "host.docker.internal" and ips and all(ip.is_private for ip in ips):
        return [str(ip) for ip in sorted(set(ips), key=lambda ip: (ip.version != 4, int(ip)))]
    if demo and parsed.hostname == "remote-demo" and ips and all(ip.is_private for ip in ips):
        return [str(ip) for ip in sorted(set(ips), key=lambda ip: (ip.version != 4, int(ip)))]
    if not ips or any(not ip.is_global for ip in ips):
        raise ValueError("Remote MCP target does not resolve exclusively to public addresses")
    return [str(ip) for ip in sorted(set(ips), key=lambda ip: (ip.version != 4, int(ip)))]


def _pinned_targets(urls: list[str]) -> dict[tuple[str, int], str]:
    targets = {}
    for url in urls:
        parsed = urlsplit(_safe_https(url))
        targets[(parsed.hostname, parsed.port or 443)] = _validate_network(url)[0]
    return targets


class _PinnedAsyncBackend(AnyIOBackend):
    def __init__(self, targets: dict[tuple[str, int], str]):
        self.targets = targets

    async def connect_tcp(self, host, port, *args, **kwargs):
        name = host.decode() if isinstance(host, bytes) else host
        target = self.targets.get((name, port))
        if target is None:
            raise ValueError("Unapproved MCP network destination")
        return await super().connect_tcp(target, port, *args, **kwargs)


class _PinnedSyncBackend(SyncBackend):
    def __init__(self, targets: dict[tuple[str, int], str]):
        self.targets = targets

    def connect_tcp(self, host, port, *args, **kwargs):
        name = host.decode() if isinstance(host, bytes) else host
        target = self.targets.get((name, port))
        if target is None:
            raise ValueError("Unapproved MCP network destination")
        return super().connect_tcp(target, port, *args, **kwargs)


def _pinned_transport(urls: list[str], verify, *, asynchronous: bool):
    """Pin the TCP destination; HTTP Host and TLS SNI remain the approved hostname.

    httpx2/httpcore2 are pinned through the MCP SDK lock. Fail closed if this
    transport's internal network backend contract changes.
    """
    targets = _pinned_targets(urls)
    cls = httpx2.AsyncHTTPTransport if asynchronous else httpx2.HTTPTransport
    transport = cls(verify=verify, trust_env=False, retries=0)
    pool = getattr(transport, "_pool", None)
    if pool is None or not hasattr(pool, "_network_backend"):
        raise RuntimeError("Pinned MCP transport backend unavailable")
    pool._network_backend = (_PinnedAsyncBackend(targets) if asynchronous
                             else _PinnedSyncBackend(targets))
    return transport


def registry() -> dict:
    raw = json.loads(get_settings().agentsentry_remote_mcp_registry)
    if not isinstance(raw, dict):
        raise ValueError("Remote MCP registry must be an object")
    for tenant_id, entry in raw.items():
        tenant_schema(tenant_id)
        required = {
                "endpoint_id", "url", "token_url", "jwks_url", "issuer", "audience",
                "client_id", "client_secret", "manifest_sha256"}
        if (not isinstance(entry, dict) or not required.issubset(entry)
                or set(entry) - required - {"ca_bundle", "ca_pem_b64"}):
            raise ValueError("Invalid remote MCP tenant registration")
        if entry["endpoint_id"] != ENDPOINT_ID:
            raise ValueError("Unknown remote MCP endpoint ID")
        for key in ("url", "token_url", "jwks_url", "issuer"):
            _safe_https(entry[key])
        if (not all(isinstance(entry[key], str) and entry[key] for key in (
                "audience", "client_id", "client_secret"))
                or not re.fullmatch(r"[0-9a-f]{64}", entry["manifest_sha256"])):
            raise ValueError("Remote MCP credentials or approved manifest missing")
        if "ca_bundle" in entry and not (isinstance(entry["ca_bundle"], str) and
                                          Path(entry["ca_bundle"]).is_file()):
            raise ValueError("Remote MCP CA bundle not found")
        if "ca_pem_b64" in entry:
            try:
                pem = base64.b64decode(entry["ca_pem_b64"], validate=True)
                ssl.create_default_context(cadata=pem.decode("ascii"))
            except (ValueError, UnicodeError, TypeError) as exc:
                raise ValueError("Remote MCP CA PEM invalid") from exc
        if "ca_bundle" in entry and "ca_pem_b64" in entry:
            raise ValueError("Choose one remote MCP CA source")
    return raw


def _tls_verify(entry: dict):
    if entry.get("ca_pem_b64"):
        pem = base64.b64decode(entry["ca_pem_b64"], validate=True).decode("ascii")
        return ssl.create_default_context(cadata=pem)
    return ssl.create_default_context(cafile=entry["ca_bundle"]) if entry.get("ca_bundle") else True


def manifest_hash(tools: list) -> str:
    return snapshot_hash(manifest_snapshot(tools))


def _token(entry: dict, scope: str) -> str:
    verify = _tls_verify(entry)
    transport = _pinned_transport([entry["token_url"], entry["jwks_url"]], verify,
                                  asynchronous=False)
    with httpx2.Client(timeout=5, follow_redirects=False, trust_env=False,
                       transport=transport) as client:
        response = client.post(entry["token_url"], data={
            "grant_type": "client_credentials", "resource": entry["audience"], "scope": scope,
        }, auth=(entry["client_id"], entry["client_secret"]))
        response.raise_for_status()
        if len(response.content) > 8192:
            raise ValueError("OAuth response too large")
        body = response.json()
        if body.get("token_type", "").lower() != "bearer" or not isinstance(body.get("access_token"), str):
            raise ValueError("OAuth bearer token missing")
        token = body["access_token"]
        if len(token) > 8192:
            raise ValueError("OAuth token too large")
        keys_response = client.get(entry["jwks_url"])
        keys_response.raise_for_status()
        if len(keys_response.content) > 16384:
            raise ValueError("OAuth JWKS too large")
        keys = jwt.PyJWKSet.from_dict(keys_response.json())
    header = jwt.get_unverified_header(token)
    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
        raise ValueError("Unsupported OAuth token signature")
    key = next((item.key for item in keys.keys if item.key_id == header["kid"]
                and item.algorithm_name == "RS256"), None)
    if key is None:
        raise ValueError("OAuth signing key not registered")
    claims = jwt.decode(token, key, algorithms=["RS256"], issuer=entry["issuer"],
                        audience=entry["audience"], options={"require": ["exp", "iss", "aud"]},
                        leeway=10)
    scopes = claims.get("scope", "").split() if isinstance(claims.get("scope"), str) else claims.get("scp", [])
    if not isinstance(scopes, list) or scope not in scopes:
        raise ValueError("OAuth token lacks required scope")
    return token


def _validate_tool(tool, name: str, fields: set[str]) -> None:
    schema = tool.input_schema
    properties = schema.get("properties", {})
    if (tool.name != name or set(properties) != fields
            or set(schema.get("required", [])) != fields
            or any(properties[item].get("type") != "string" for item in fields)):
        raise ValueError("Registered remote MCP tool schema changed")


def _validate_result(tool: str, arguments: dict, result: dict) -> dict:
    if len(json.dumps(result, ensure_ascii=False).encode()) > 4096:
        raise ValueError("Remote MCP result too large")
    if tool == "remote_mcp_lookup_card":
        if result == {"error": "card_not_found"}:
            return result
        if (set(result) != {"card_id", "content"} or result["card_id"] != arguments["card_id"]
                or not isinstance(result["content"], str)):
            raise ValueError("Remote MCP card result invalid")
    elif (set(result) != {"note_id", "recorded"}
          or result["note_id"] != arguments["note_id"] or result["recorded"] is not True):
        raise ValueError("Remote MCP note result invalid")
    return result


def _is_manifest_drift(exc: BaseException) -> bool:
    if isinstance(exc, BaseExceptionGroup):
        return any(_is_manifest_drift(item) for item in exc.exceptions)
    return isinstance(exc, ValueError) and any(marker in str(exc).lower() for marker in (
        "manifest", "tool schema", "tool unavailable"))


async def _check_canary(session: ClientSession) -> str:
    """A narrow synthetic behavior check; it is not remote-code attestation."""
    response = await session.call_tool("lookup_card", arguments={"card_id": CANARY_CARD})
    if response.is_error or not isinstance(response.structured_content, dict):
        raise ValueError("Remote MCP behavior canary unavailable")
    result = _validate_result("remote_mcp_lookup_card", {"card_id": CANARY_CARD},
                              response.structured_content)
    if "content" not in result:
        raise ValueError("Remote MCP behavior canary unavailable")
    digest = hashlib.sha256(result["content"].encode()).hexdigest()
    if digest != CANARY_CONTENT_SHA256:
        raise ValueError("Remote MCP behavior canary drift:" + digest)
    return digest


async def _call_upstream(entry: dict, tool: str, arguments: dict, call_id: str,
                         token: str, sent: dict) -> dict:
    name, _, fields = UPSTREAM[tool]
    verify = _tls_verify(entry)
    transport = _pinned_transport([entry["url"]], verify, asynchronous=True)
    async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + token},
            timeout=httpx2.Timeout(8, read=8), follow_redirects=False,
            trust_env=False, transport=transport) as client:
        async with streamable_http_client(entry["url"], http_client=client) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=8) as session:
                await session.discover()
                listed = await session.list_tools()
                if listed.next_cursor or len(listed.tools) > 20:
                    raise ValueError("Remote MCP manifest unexpectedly paginated or oversized")
                snapshot = manifest_snapshot(listed.tools)
                observed_hash = snapshot_hash(snapshot)
                if observed_hash != entry["manifest_sha256"]:
                    sent["observed_manifest"] = snapshot
                    raise ValueError("Remote MCP manifest drift; administrator review required")
                matches = [item for item in listed.tools if item.name == name]
                if len(matches) != 1:
                    sent["observed_manifest"] = snapshot
                    raise ValueError("Registered remote MCP tool unavailable")
                try:
                    _validate_tool(matches[0], name, fields)
                except ValueError:
                    sent["observed_manifest"] = snapshot
                    raise
                if tool == "remote_mcp_lookup_card":
                    try:
                        await _check_canary(session)
                    except ValueError as exc:
                        sent["behavior_drift"] = True
                        if "drift:" in str(exc):
                            sent["observed_canary_sha256"] = str(exc).rsplit(":", 1)[-1]
                        raise
                upstream_arguments = dict(arguments)
                if tool == "remote_mcp_record_note":
                    upstream_arguments["operation_id"] = call_id
                sent["value"] = True
                response = await session.call_tool(name, arguments=upstream_arguments)
                if response.is_error or not isinstance(response.structured_content, dict):
                    raise ValueError("Remote MCP returned an error or unstructured result")
                result = _validate_result(tool, arguments, response.structured_content)
                result["_remote"] = {"endpoint_id": ENDPOINT_ID, "protocol": PROTOCOL,
                                      "manifest_sha256": entry["manifest_sha256"]}
                return result


def execute_remote_mcp(tool: str, arguments: dict, call_id: str, tenant_id: str,
                       db=None) -> dict:
    if tool not in UPSTREAM:
        raise ValueError("Unknown remote MCP tool")
    tenant_schema(tenant_id)
    try:
        entry = registry()[tenant_id]
    except (KeyError, ValueError, json.JSONDecodeError):
        return {"error": "remote_mcp_not_registered", "endpoint_id": ENDPOINT_ID}
    entry = dict(entry)
    if db is not None:
        seed_baseline(db, entry)
        # A shared database row lock keeps administrator profile changes from
        # taking effect halfway through this already-approved tool dispatch.
        profile = active_profile(db, hold_for_call=True)
        if profile is None:
            return {"error": "remote_mcp_profile_drift", "endpoint_id": ENDPOINT_ID,
                    "protocol": PROTOCOL}
        if profile.config_hash != config_hash(entry):
            return {"error": "remote_mcp_profile_drift", "endpoint_id": ENDPOINT_ID,
                    "protocol": PROTOCOL, "manifest_sha256": profile.manifest_sha256}
        entry["manifest_sha256"] = profile.manifest_sha256
    sent = {"value": False}
    try:
        if tool == "remote_mcp_record_note":
            # A write token only has notes.write. Verify the synthetic read-only
            # canary using a separate, least-privilege cards.read token.
            read_token = _token(entry, "cards.read")
            before_write = asyncio.run(asyncio.wait_for(
                _probe_upstream(entry, read_token), timeout=12))
            if before_write["status"] != "healthy":
                if db is not None and before_write["status"] == "drift":
                    record_candidate(db, entry, before_write["observed_manifest"])
                if db is not None and before_write["status"] == "behavior_drift":
                    record_incident(db, "behavior_canary", call_id=call_id,
                                    expected_sha256=CANARY_CONTENT_SHA256,
                                    observed_sha256=before_write.get("observed_canary_sha256"))
                return {"error": ("remote_mcp_behavior_drift" if before_write["status"] == "behavior_drift"
                                  else "remote_mcp_manifest_drift"),
                        "endpoint_id": ENDPOINT_ID, "protocol": PROTOCOL,
                        "manifest_sha256": entry["manifest_sha256"]}
        token = _token(entry, UPSTREAM[tool][1])
        return asyncio.run(asyncio.wait_for(
            _call_upstream(entry, tool, arguments, call_id, token, sent), timeout=20))
    except Exception as exc:
        if sent["value"]:
            raise  # The remote side may have committed; never retry the write.
        drift = _is_manifest_drift(exc)
        if drift and db is not None and sent.get("observed_manifest"):
            record_candidate(db, entry, sent["observed_manifest"])
        if sent.get("behavior_drift") and db is not None:
            record_incident(db, "behavior_canary", call_id=call_id,
                            expected_sha256=CANARY_CONTENT_SHA256,
                            observed_sha256=sent.get("observed_canary_sha256"))
        return {"error": ("remote_mcp_behavior_drift" if sent.get("behavior_drift") else
                          "remote_mcp_manifest_drift" if drift else "remote_mcp_unavailable"),
                "endpoint_id": ENDPOINT_ID,
                "protocol": PROTOCOL, "manifest_sha256": entry["manifest_sha256"]}


async def _probe_upstream(entry: dict, token: str, *, check_canary: bool = True) -> dict:
    verify = _tls_verify(entry)
    transport = _pinned_transport([entry["url"]], verify, asynchronous=True)
    async with httpx2.AsyncClient(headers={"Authorization": "Bearer " + token},
            timeout=httpx2.Timeout(5, read=5), follow_redirects=False,
            trust_env=False, transport=transport) as client:
        async with streamable_http_client(entry["url"], http_client=client) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=5) as session:
                await session.discover()
                listed = await session.list_tools()
                snapshot = manifest_snapshot(listed.tools)
                digest = snapshot_hash(snapshot)
                registered = {item.name: item for item in listed.tools}
                shapes_ok = not listed.next_cursor and len(listed.tools) <= 20
                for name, _, fields in UPSTREAM.values():
                    try:
                        _validate_tool(registered[name], name, fields)
                    except (KeyError, ValueError):
                        shapes_ok = False
                status = "healthy" if shapes_ok and digest == entry["manifest_sha256"] else "drift"
                observed_canary = None
                if status == "healthy" and check_canary:
                    try:
                        observed_canary = await _check_canary(session)
                    except ValueError as exc:
                        status = "behavior_drift"
                        if "drift:" in str(exc):
                            observed_canary = str(exc).rsplit(":", 1)[-1]
                return {"status": status,
                        "observed_manifest_sha256": digest, "tool_count": len(listed.tools),
                        "protocol_version": session.protocol_version,
                        "observed_manifest": snapshot,
                        "expected_canary_sha256": CANARY_CONTENT_SHA256,
                        "observed_canary_sha256": observed_canary,
                        "canary_checked": check_canary and status != "drift"}


def probe_remote_mcp(tenant_id: str, db=None, *, record: bool = False) -> dict:
    tenant_schema(tenant_id)
    try:
        entry = registry()[tenant_id]
    except (KeyError, ValueError, json.JSONDecodeError):
        return {"status": "unregistered", "endpoint_id": ENDPOINT_ID, "protocol": PROTOCOL}
    entry = dict(entry)
    profile = active_profile(db) if db is not None else None
    if profile:
        entry["manifest_sha256"] = profile.manifest_sha256
    view = {"endpoint_id": ENDPOINT_ID, "protocol": PROTOCOL,
            "url": entry["url"], "approved_manifest_sha256": entry["manifest_sha256"],
            "profile_revision": profile.revision if profile else None,
            "registration_changed": bool(profile and profile.config_hash != config_hash(entry))}
    try:
        token = _token(entry, "cards.read")
        view.update(asyncio.run(asyncio.wait_for(
            _probe_upstream(entry, token, check_canary=record), timeout=12)))
        if view["registration_changed"]:
            view["status"] = "registration_changed"
        if record and db is not None and (view["status"] in {"drift", "registration_changed"}):
            candidate = record_candidate(db, entry, view["observed_manifest"])
            db.commit()
            view["candidate_id"] = candidate.id
        elif record and db is not None and view["status"] == "behavior_drift":
            record_incident(db, "behavior_canary", expected_sha256=CANARY_CONTENT_SHA256,
                            observed_sha256=view.get("observed_canary_sha256"))
            db.commit()
        elif record and db is not None and view["status"] == "healthy" and profile and not profile.manifest:
            profile.manifest = view["observed_manifest"]
            db.commit()
    except Exception:
        view["status"] = "unavailable_or_auth_failed"
    view.pop("observed_manifest", None)
    return view
