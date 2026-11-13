"""v0.7: LiteLLM guardrail."""
import asyncio

import pytest

pytest.importorskip("litellm")

from shinafure.integrations import litellm_guard as lg  # noqa: E402


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def demo():
    det, cs = lg.demo_detector()
    yield det, cs
    lg._state.update(detector=None, policy="flag")


def chat(text):
    return {"model": "m", "messages": [{"role": "system", "content": "整形して"},
                                       {"role": "user", "content": [{"type": "text", "text": text}]}]}


def test_flag_passes_and_records(demo):
    det, cs = demo
    g = lg.ShinafureGuardrail(detector=det, policy="flag", guardrail_name="shinafure")
    out = run(g.async_pre_call_hook(None, None, chat(f"顧客: {cs[0].person['email']}"), "acompletion"))
    assert out["metadata"]["shinafure"]["confirmed"] == 1


def test_block_refuses_only_canaries(demo):
    det, cs = demo
    g = lg.ShinafureGuardrail(detector=det, policy="block", guardrail_name="shinafure")
    clean = run(g.async_pre_call_hook(None, None, chat("田中太郎 090-1111-2222"), "acompletion"))
    assert clean["metadata"]["shinafure"]["confirmed"] == 0
    with pytest.raises(Exception) as e:
        run(g.async_pre_call_hook(None, None, chat(f"{cs[1].person['last']}{cs[1].person['first']} {cs[1].person['phone']}"), "acompletion"))
    assert getattr(e.value, "status_code", 403) == 403


def test_text_is_collected_from_every_request_shape():
    assert lg.request_text({"input": ["a", "b"]}) == "a\nb"
    assert lg.request_text({"prompt": "p", "messages": [{"content": [{"type": "text", "text": "t"}, {"type": "image_url"}]}]}) == "t\np"
    assert lg.request_text({"messages": [{"role": "assistant", "tool_calls": []}]}) == ""


def test_no_detector_means_no_op():
    lg._state.update(detector=None)
    g = lg.ShinafureGuardrail(guardrail_name="shinafure")
    d = chat("x")
    assert run(g.async_pre_call_hook(None, None, d, "acompletion")) is d
