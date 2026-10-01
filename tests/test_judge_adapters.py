import json

import pytest

from agentsentry.config import Settings
from agentsentry.judge import adapters


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self.body


class FakeClient:
    def __init__(self, body):
        self.body = body
        self.request = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def post(self, url, **kwargs):
        self.request = (url, kwargs)
        return FakeResponse(self.body)


def test_openai_compatible_adapter_validates_normalized_result(monkeypatch):
    fake = FakeClient({
        "model": "example-model",
        "choices": [{"message": {"content": json.dumps({
            "labels": ["prompt_injection"], "score": 0.8,
        })}}],
    })
    monkeypatch.setattr(adapters.httpx, "Client", lambda **_: fake)
    settings = Settings(judge_openai_base_url="https://example.invalid/v1", judge_openai_model="example-model")
    verdict = adapters.OpenAICompatibleJudge(settings).evaluate({
        "type": "tool_result",
        "payload": {"tool": "read_document", "result": {
            "sensitivity": "private", "content": "private-value-7319",
        }},
    }, "event-1")
    assert verdict.labels == ["prompt_injection"] and verdict.score == 0.8
    assert "private-value-7319" not in str(fake.request)


def test_jev_adapter_maps_typed_probabilities(monkeypatch):
    fake = FakeClient({
        "model": "jev-version",
        "answers": {
            "prompt_injection": {"type": "noul", "noul": 0.91},
            "exfiltration": {"type": "noul", "noul": 0.2},
            "tool_misuse": {"type": "noul", "noul": 0.1},
        },
    })
    monkeypatch.setattr(adapters.httpx, "Client", lambda **_: fake)
    settings = Settings(jev_api_key="test-only")
    verdict = adapters.JevJudge(settings).evaluate({"type": "tool_result", "payload": {}}, "event-2")
    assert verdict.labels == ["prompt_injection"]
    assert verdict.score == 0.91
    assert fake.request[0].endswith("/v1/systemone")
    assert fake.request[1]["headers"]["Idempotency-Key"] == "event-2"


def test_deepseek_adapter_uses_json_mode_and_redacts_private_content(monkeypatch):
    fake = FakeClient({
        "model": "deepseek-flash",
        "choices": [{"finish_reason": "stop", "message": {"content": json.dumps({
            "labels": ["none"], "score": 0.1,
        })}}],
    })
    monkeypatch.setattr(adapters.httpx, "Client", lambda **_: fake)
    settings = Settings(deepseek_api_key="test-only")
    verdict = adapters.DeepSeekJudge(settings).evaluate({
        "type": "tool_result", "payload": {"tool": "read_document", "result": {
            "sensitivity": "private", "content": "private-value-7319",
        }},
    }, "event-3")
    assert verdict.provider == "deepseek" and verdict.labels == ["none"]
    url, request = fake.request
    assert url == "https://api.deepseek.com/chat/completions"
    assert request["headers"]["Authorization"] == "Bearer test-only"
    assert request["json"]["model"] == "deepseek-flash"
    assert request["json"]["response_format"] == {"type": "json_object"}
    assert request["json"]["thinking"] == {"type": "disabled"}
    assert "private-value-7319" not in str(request)


@pytest.mark.parametrize("content,finish_reason", [("", "stop"), ('{"labels":["none"', "length")])
def test_deepseek_adapter_rejects_empty_or_truncated_json(monkeypatch, content, finish_reason):
    fake = FakeClient({
        "choices": [{"finish_reason": finish_reason, "message": {"content": content}}],
    })
    monkeypatch.setattr(adapters.httpx, "Client", lambda **_: fake)
    with pytest.raises(ValueError):
        adapters.DeepSeekJudge(Settings(deepseek_api_key="test-only")).evaluate(
            {"type": "tool_result", "payload": {}}, "event-4",
        )
