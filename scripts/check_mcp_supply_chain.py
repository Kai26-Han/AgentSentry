"""核对 MCP 连接代码依赖的固定版本及锁文件；不声称远端代码完整性。"""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {"mcp": "2.2.0", "httpx2": "2.13.1", "httpcore2": "2.13.1"}


def check() -> dict[str, str]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    dependencies = set(project["project"]["dependencies"])
    locked = {item["name"]: item["version"] for item in lock["package"]}
    for package, expected in EXPECTED.items():
        if f"{package}=={expected}" not in dependencies:
            raise ValueError(f"{package} 缺少固定的直接依赖版本 {expected}")
        if locked.get(package) != expected:
            raise ValueError(f"{package} 锁文件版本不匹配")
        try:
            installed = version(package)
        except PackageNotFoundError as exc:
            raise ValueError(f"{package} 未安装") from exc
        if installed != expected:
            raise ValueError(f"{package} 当前环境版本不匹配：{installed}")
    return EXPECTED


if __name__ == "__main__":
    print("MCP 依赖版本核对通过：" + ", ".join(
        f"{package}={revision}" for package, revision in check().items()))
