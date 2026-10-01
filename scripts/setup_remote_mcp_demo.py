"""生成本机受控远程 MCP 演示所需的 TLS 证书与私有配置。"""

import asyncio
import base64
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from agentsentry.mcp_remote import manifest_hash
from agentsentry.mcp_remote_server import server


ROOT = Path(__file__).resolve().parents[1]


def _certificate(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = directory / "server.crt", directory / "server.key"
    if cert_path.exists() and key_path.exists():
        return
    if cert_path.exists() or key_path.exists():
        raise RuntimeError("证书或私钥仅存在一份，请先人工检查")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "remote-demo")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(private_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("remote-demo")]), critical=False)
        .sign(private_key, hashes.SHA256()))
    key_path.write_bytes(private_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    os.chmod(key_path, 0o600)
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def main() -> None:
    env_path = ROOT / ".env"
    if not env_path.is_file():
        raise RuntimeError("请先准备项目 .env")
    lines = env_path.read_text(encoding="utf-8").splitlines()
    existing = {}
    for line in lines:
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            existing[key] = value
    current_registry = existing.get("AGENTSENTRY_REMOTE_MCP_REGISTRY", "{}")
    if current_registry not in ("", "{}"):
        try:
            old = json.loads(current_registry)["default"]
        except (ValueError, KeyError, TypeError) as exc:
            raise RuntimeError("远程 MCP 已有登记配置；脚本不会覆盖") from exc
        if old.get("endpoint_id") != "remote-demo" or old.get("url") != "https://remote-demo:9443/mcp":
            raise RuntimeError("远程 MCP 已有非本机演示登记；脚本不会覆盖")
    cert_dir = ROOT / ".local" / "remote-mcp-certs"
    _certificate(cert_dir)
    certificate = (cert_dir / "server.crt").read_bytes()
    private_key = (cert_dir / "server.key").read_bytes()
    demo_env = ROOT / ".local" / "remote-demo.env"
    demo_env.write_text("REMOTE_MCP_DEMO_CERT_B64=" + base64.b64encode(certificate).decode() +
                        "\nREMOTE_MCP_DEMO_KEY_B64=" + base64.b64encode(private_key).decode() + "\n",
                        encoding="utf-8")
    os.chmod(demo_env, 0o600)
    secret = existing.get("REMOTE_MCP_DEMO_CLIENT_SECRET") or secrets.token_urlsafe(40)
    origin = "https://remote-demo:9443"
    registration = {"default": {"endpoint_id": "remote-demo", "url": origin + "/mcp",
        "token_url": origin + "/token", "jwks_url": origin + "/jwks", "issuer": origin,
        "audience": origin + "/mcp", "client_id": "demo-client",
        "client_secret": secret,
        "manifest_sha256": manifest_hash(asyncio.run(server.list_tools())),
        "ca_pem_b64": base64.b64encode(certificate).decode()}}
    updates = {"REMOTE_MCP_DEMO_CLIENT_SECRET": secret,
        "AGENTSENTRY_REMOTE_MCP_REGISTRY": json.dumps(registration, separators=(",", ":")),
        "AGENTSENTRY_REMOTE_MCP_ENABLED": "true",
        "AGENTSENTRY_REMOTE_MCP_ALLOW_LOOPBACK_DEMO": "true"}
    result = []
    seen = set()
    for line in lines:
        key = line.split("=", 1)[0] if "=" in line and not line.startswith("#") else None
        if key in updates:
            if key not in seen:
                result.append(key + "=" + updates[key])
                seen.add(key)
        else:
            result.append(line)
    result.extend(key + "=" + value for key, value in updates.items() if key not in seen)
    temporary = env_path.with_name(".env.remote-mcp.tmp")
    temporary.write_text("\n".join(result) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(env_path)
    print("已生成本机演示证书与 .env 登记；未输出凭据。")
    print("下一步：docker compose --profile remote-mcp-demo up --build -d")


if __name__ == "__main__":
    main()
