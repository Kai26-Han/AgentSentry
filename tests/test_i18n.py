"""界面语言隔离、证据不改写、授权边界和翻译目录完整性。"""
import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from jinja2 import nodes

from agentsentry import main
from agentsentry.config import get_settings
from agentsentry.database import get_engine, get_session_factory
from agentsentry.evaluation import MemoryRedis
from agentsentry.i18n import LANGUAGE_COOKIE, english_catalog, switch_url
from agentsentry.runtime_guard import rule_catalog
from agentsentry.data_flow import rule_catalog as data_flow_rule_catalog


@pytest.fixture
def web(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/languages.db")
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    settings = get_settings()
    monkeypatch.setattr(main, "settings", settings)
    monkeypatch.setattr(main, "serializer", main.URLSafeTimedSerializer(
        settings.session_secret, salt="agentsentry-admin"))
    store = MemoryRedis()
    monkeypatch.setattr(main, "get_redis", lambda: store)
    with TestClient(main.app) as client:
        yield client
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    get_settings.cache_clear()


def test_login_switch_persists_without_sharing_language_between_clients(web):
    assert '<html lang="zh">' in web.get('/login').text
    assert '管理员密码' in web.get('/login').text
    response = web.get('/ui-language/en?next=/login', follow_redirects=False)
    assert response.status_code == 303 and response.headers['location'] == '/login'
    assert web.cookies[LANGUAGE_COOKIE] == 'en'
    assert 'HttpOnly' in response.headers['set-cookie']
    english = web.get('/login').text
    assert '<html lang="en">' in english and 'Administrator password' in english
    assert '管理员密码' not in english
    with TestClient(main.app) as other:
        assert '<html lang="zh">' in other.get('/login').text
        assert LANGUAGE_COOKIE not in other.cookies
    web.get('/ui-language/zh?next=/login')
    assert '管理员密码' in web.get('/login').text
    web.cookies.set(LANGUAGE_COOKIE, 'unsupported')
    assert '<html lang="zh">' in web.get('/login').text


def test_english_pages_navigation_and_api_authorization_are_independent(web):
    web.get('/ui-language/en?next=/login')
    assert web.get('/api/v2/tenants').status_code == 401
    web.post('/login', data={'password': main.settings.admin_password})
    pages = ['/dashboard', '/dashboard/runtime-sessions', '/dashboard/activity',
             '/dashboard/delegations', '/dashboard/action-chains', '/dashboard/goal-assessments',
             '/dashboard/data-flow', '/dashboard/audit', '/dashboard/alerts', '/dashboard/approvals',
             '/dashboard/memories', '/dashboard/memory-runs', '/dashboard/memory-security-runs',
             '/dashboard/attack-runs', '/dashboard/calibration-runs', '/dashboard/goal-runs',
             '/dashboard/judge-samples', '/dashboard/grants', '/dashboard/policy',
             '/dashboard/runtime-rules', '/dashboard/judge-runtime', '/dashboard/remote-mcp',
             '/dashboard/tenants', '/dashboard/system', '/dashboard/resilience',
             '/dashboard/threat-map', '/dashboard/threat-map?view=framework',
             '/dashboard/threat-map/threats/TH-001']
    for path in pages:
        response = web.get(path)
        assert response.status_code == 200, path
        assert '<html lang="en">' in response.text, path
        assert 'aria-label="Main navigation"' in response.text, path
        assert 'Session investigation' in response.text, path
        assert 'aria-label="主目录"' not in response.text, path
    rules = web.get('/dashboard/runtime-rules').text
    assert 'Runtime security rules' in rules and 'At least three calls' in rules
    assert '最近 10 分钟' not in rules
    assert 'Parameters changed' not in rules
    # Language preferences never grant authorization or remove CSRF checks.
    assert web.post('/api/v1/capabilities', json={
        'tool': 'read_document', 'agent_id': 'demo-agent', 'resources': ['public-guide'],
        'ttl_seconds': 600, 'max_uses': 1}).status_code == 403
    assert web.post('/logout').status_code == 403
    web.get('/ui-language/zh?next=/dashboard/approvals')
    assert '审批' in web.get('/dashboard/approvals').text


@pytest.mark.parametrize('target', [
    'https://evil.example/', '//evil.example/', '/%2f%2fevil.example/',
    '/\\evil.example/', '/dashboard%0d%0aLocation:evil', '//[',
    '/api/v1/tool-calls', '/logout', '/ui-language/en', '/' + 'x' * 5000])
def test_language_switch_cannot_redirect_offsite_or_to_action_endpoints(web, target):
    response = web.get('/ui-language/en', params={'next': target}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers['location'] == '/dashboard'


def test_language_return_preserves_research_context_and_rejects_unknown_languages(web):
    target = '/dashboard/memory-runs?tenant=research-example&view=results'
    response = web.get('/ui-language/en', params={'next': target}, follow_redirects=False)
    assert response.headers['location'] == target
    from starlette.requests import Request
    request = Request({'type': 'http', 'scheme': 'http', 'server': ('localhost', 8000),
                       'path': '/dashboard/memory-runs', 'query_string': b'tenant=research-example',
                       'headers': []})
    assert parse_qs(urlsplit(switch_url(request, 'zh')).query)['next'] == [
        '/dashboard/memory-runs?tenant=research-example']
    previous = web.cookies[LANGUAGE_COOKIE]
    assert web.get('/ui-language/fr').status_code == 400
    assert web.cookies[LANGUAGE_COOKIE] == previous


def test_translation_preserves_original_text_and_escapes_catalog_values(monkeypatch):
    raw = '总览 <script>alert(1)</script>'
    template = main.templates.env.from_string('{{ text }}|{{ payload|tojson }}|{{ code }}')
    rendered = template.render(ui_language='en', text=raw, payload={'text': '总览'}, code='require_approval')
    assert '总览 &lt;script&gt;' in rendered
    assert '\\u603b\\u89c8' in rendered
    assert rendered.endswith('require_approval')
    structured = main.templates.env.from_string('{{ payload|ui|tojson }}').render(
        ui_language='en', payload={'text': '总览', 'state': '已批准'})
    import json
    assert json.loads(structured) == {'text': '总览', 'state': '已批准'}
    monkeypatch.setitem(english_catalog(), '总览', '<img src=x onerror=alert(1)>')
    translated = main.templates.env.from_string('{{ _("总览") }}').render(ui_language='en')
    assert '<img ' not in translated and '&lt;img ' in translated


def test_english_approval_preserves_original_parameters_and_confirmation_checks(web):
    import json
    import uuid
    web.get('/ui-language/en?next=/login')
    web.post('/login', data={'password': main.settings.admin_password})
    csrf = main.serializer.loads(web.cookies['agentsentry_session'])['csrf']
    agent = {'Authorization': 'Bearer ' + main.settings.agent_api_key}
    session = web.put('/api/v2/runtime-sessions/language-approval/start', headers=agent,
                      json={'transport': 'http', 'capture_mode': 'preview', 'user_task': '总览'})
    assert session.status_code == 200
    grant = web.post('/api/v1/capabilities', headers={'X-CSRF-Token': csrf}, json={
        'tool': 'send_external', 'agent_id': 'demo-agent', 'resources': ['demo-inbox'],
        'ttl_seconds': 600, 'max_uses': 1})
    arguments = {'destination_id': 'demo-inbox', 'content': '总览 <script>alert(1)</script>'}
    call = web.post('/api/v1/tool-calls', headers={**agent, 'X-Capability': grant.json()['token'],
        'X-Runtime-Session': session.json()['session_token']}, json={
            'call_id': str(uuid.uuid4()), 'session_id': 'language-approval',
            'tool': 'send_external', 'arguments': arguments})
    assert call.status_code == 202
    path = '/dashboard/approvals/' + call.json()['approval_id']
    page = web.get(path)
    assert 'Gateway-verified facts' in page.text
    assert 'Confirm approval of the original action' in page.text
    raw = re.search(r'<summary>Expand full original parameters</summary><pre>(.*?)</pre>', page.text, re.S)
    assert json.loads(raw.group(1)) == arguments
    assert '<script>alert(1)</script>' not in page.text
    assert web.post(path, data={'decision': 'approve'}).status_code == 403
    assert web.post(path, data={'csrf': csrf, 'decision': 'approve'}).status_code == 422
    assert '总览' in web.get('/dashboard/runtime-sessions/detail?session_id=language-approval&agent_id=demo-agent').text


def test_all_static_interface_and_rule_strings_have_english_translations():
    catalog = english_catalog()
    folder = Path(main.templates.env.loader.searchpath[0])
    missing = set()
    for path in folder.glob('*.html'):
        tree = main.templates.env.parse(path.read_text())
        for node in tree.find_all(nodes.Call):
            if isinstance(node.node, nodes.Name) and node.node.name == '_' and node.args:
                if isinstance(node.args[0], nodes.Const) and node.args[0].value not in catalog:
                    missing.add(node.args[0].value)
    for rule in rule_catalog() + data_flow_rule_catalog():
        for key in ('title', 'category', 'scope', 'trigger', 'effect', 'evidence', 'limit'):
            text = rule.get(key, '')
            if re.search('[\u3400-\u9fff]', text) and text not in catalog:
                missing.add(text)
    assert not missing, sorted(missing)
