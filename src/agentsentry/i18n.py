"""Web 界面翻译：每个请求独立选语言，不改变审计与操作数据。"""
import json
from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote, urlencode, urlsplit

from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse
from jinja2 import pass_context

LANGUAGE_COOKIE = "agentsentry_language"
SUPPORTED_LANGUAGES = ("zh", "en")
CATALOG_PATH = Path(__file__).parent / "locales" / "en.json"


@lru_cache(maxsize=1)
def english_catalog() -> dict[str, str]:
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    if not isinstance(catalog, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                          or not v.strip() for k, v in catalog.items()):
        raise ValueError("界面翻译目录格式错误")
    return catalog


def language_for(request: Request) -> str:
    language = request.cookies.get(LANGUAGE_COOKIE, "zh")
    return language if language in SUPPORTED_LANGUAGES else "zh"


def translate(value: str, language: str) -> str:
    return english_catalog().get(value, value) if language == "en" else value


@pass_context
def gettext(context, value):
    return translate(str(value), context.get("ui_language", "zh"))


@pass_context
def ui_value(context, value):
    """仅用于模板显式标记的界面描述，不在原始正文或 JSON 上调用。"""
    if isinstance(value, str):
        return translate(value, context.get("ui_language", "zh"))
    return value


def switch_url(request: Request, language: str) -> str:
    path = request.url.path
    if request.url.query:
        path += "?" + request.url.query
    return "/ui-language/" + language + "?" + urlencode({"next": path})


def safe_return_path(value: str) -> str:
    # Only relative paths on this application are allowed; also reject encoded
    # authority delimiters, browser backslash normalization and control characters.
    decoded = value
    for _ in range(3):
        decoded = unquote(decoded)
    try:
        parsed = urlsplit(decoded)
    except ValueError:
        return "/dashboard"
    if (len(value) > 4096 or not decoded.startswith("/") or decoded.startswith("//")
            or "\\" in decoded or parsed.scheme or parsed.netloc
            or any(ord(c) < 32 or ord(c) == 127 for c in decoded)
            or not (parsed.path == "/login" or parsed.path == "/dashboard"
                    or parsed.path.startswith("/dashboard/"))):
        return "/dashboard"
    return value


def install(templates, app):
    templates.env.globals.update(_=gettext, switch_language_url=switch_url)
    templates.env.filters["ui"] = ui_value
    templates.context_processors.append(lambda request: {"ui_language": language_for(request)})

    @app.get("/ui-language/{language}", include_in_schema=False)
    def set_language(language: str, request: Request, next: str = "/dashboard"):
        if language not in SUPPORTED_LANGUAGES:
            raise HTTPException(400, "Unsupported interface language")
        response = RedirectResponse(safe_return_path(next), status_code=303)
        response.set_cookie(LANGUAGE_COOKIE, language, max_age=365 * 24 * 3600,
                            httponly=True, samesite="lax", secure=request.url.scheme == "https")
        return response
