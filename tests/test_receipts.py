import hashlib
import importlib
import json
import os
import sys
import threading
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(ROOT))
spec = importlib.util.spec_from_file_location("receipts", os.path.join(ROOT, "receipts.py"))
receipts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipts)

SMART = dict(command="rm -rf /tmp/build", description="recursive delete", pattern_key="rm_rf", pattern_keys=["rm_rf"],
             session_key="cron:nightly", surface="smart", choice="smart_deny", decided_by="aux_llm",
             tool_call_id="call_1", turn_id="t1")


def test_guardian_scope_only_takes_guardian_verdicts():
    assert receipts.wanted(SMART, "guardian") == "deny"
    assert receipts.wanted(dict(SMART, choice="smart_approve"), "guardian") == "approve"
    human = dict(SMART, choice="once", surface="cli", decided_by=None)
    assert receipts.wanted(human, "guardian") is None
    assert receipts.wanted(human, "all") == "approve"


def test_non_decisions_get_no_receipt():
    for c in ("timeout", "cancelled", "notify_failed", "escalate", "", None):
        assert receipts.wanted(dict(SMART, choice=c), "all") is None


def test_command_never_leaves_the_machine():
    n = receipts.new_nonce()
    body = receipts.request_body(SMART, "deny", n)
    wire = receipts.canonical(body).decode()
    for secret in ("rm -rf", "/tmp/build", "recursive delete", "cron:nightly"):
        assert secret not in wire
    assert set(body) == {"question", "options", "choice", "context_sha256", "decider"}
    assert body["choice"] in body["options"]


def test_nonce_makes_the_hash_unguessable_and_reproducible_by_the_holder():
    n1, n2 = receipts.new_nonce(), receipts.new_nonce()
    assert receipts.context_sha256(SMART, n1) != receipts.context_sha256(SMART, n2)
    ctx = receipts.context_of(SMART, n1)
    assert hashlib.sha256(receipts.canonical(ctx)).hexdigest() == receipts.context_sha256(SMART, n1)


def test_record_keeps_what_opens_the_receipt():
    n = receipts.new_nonce()
    body = receipts.request_body(SMART, "deny", n)
    resp = {"event": {"id": "e1"}, "receipt": {"choice_commitment": "c"}, "reveal": {"salt": "s1"}}
    rec = receipts.record(resp, SMART, body, n)
    assert rec["salt"] == "s1" and rec["context"]["nonce"] == n and rec["receipt_event_id"] == "e1"
    assert hashlib.sha256(receipts.canonical(rec["context"])).hexdigest() == rec["context_sha256"]


def _load_plugin(tmp_path, monkeypatch, post):
    pkg = types.ModuleType("ivv_plugin"); pkg.__path__ = [ROOT]
    sys.modules["ivv_plugin"] = pkg
    sys.modules["ivv_plugin.receipts"] = receipts
    spec2 = importlib.util.spec_from_file_location("ivv_plugin.__init__", os.path.join(ROOT, "__init__.py"),
                                                   submodule_search_locations=[ROOT])
    mod = importlib.util.module_from_spec(spec2); mod.__package__ = "ivv_plugin"; spec2.loader.exec_module(mod)
    monkeypatch.setattr(receipts, "post_receipt", post)
    out = tmp_path / "receipts.jsonl"
    monkeypatch.setattr(mod, "_data_file", lambda: out)
    hooks = {}
    ctx = types.SimpleNamespace(get_config=lambda k, default=None: default,
                                register_hook=lambda name, fn: hooks.setdefault(name, fn))
    mod.register(ctx)
    return hooks, out


def _join():
    for t in threading.enumerate():
        if t.name == "invinoveritas-receipt":
            t.join(5)


def test_hook_issues_a_receipt_off_the_approval_path(tmp_path, monkeypatch):
    monkeypatch.setenv("INVINOVERITAS_API_KEY", "ivv_test")
    sent = []
    hooks, out = _load_plugin(tmp_path, monkeypatch, lambda url, key, body, t: sent.append(body) or
                              {"event": {"id": "ev"}, "receipt": {}, "reveal": {"salt": "ss"}})
    assert hooks["post_approval_response"](**SMART) is None
    _join()
    assert len(sent) == 1 and sent[0]["choice"] == "deny"
    rec = json.loads(out.read_text().strip())
    assert rec["receipt_event_id"] == "ev" and rec["salt"] == "ss"


def test_a_failing_api_never_reaches_hermes(tmp_path, monkeypatch):
    monkeypatch.setenv("INVINOVERITAS_API_KEY", "ivv_test")
    def boom(*a, **k):
        raise OSError("network down")
    hooks, out = _load_plugin(tmp_path, monkeypatch, boom)
    assert hooks["post_approval_response"](**SMART) is None
    _join()
    assert not out.exists()


def test_human_decisions_are_skipped_in_guardian_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("INVINOVERITAS_API_KEY", "ivv_test")
    sent = []
    hooks, _ = _load_plugin(tmp_path, monkeypatch, lambda *a: sent.append(a) or {})
    hooks["post_approval_response"](**dict(SMART, choice="once", decided_by=None, surface="cli"))
    _join()
    assert sent == []


# ---- turn-end receipts (0.2.0, NousResearch/hermes-agent#16004) ----
def _todo_msg(statuses):
    todos = [{"id": str(i), "content": f"stage {i}", "status": s} for i, s in enumerate(statuses)]
    summary = {"total": len(todos)}
    return {"role": "tool", "tool_call_id": "c", "content": json.dumps({"todos": todos, "revision": 3, "summary": summary})}


# James Wilson's field case: an ordered multi-stage directive, 11 obligations, turn stops at max_iterations 24/24.
HISTORY = [{"role": "user", "content": "do the ordered workflow"},
           _todo_msg(["completed"] * 2 + ["in_progress"] * 5 + ["pending"] * 4),
           {"role": "assistant", "content": "Status: all stages handled."}]
END = dict(session_id="s1", turn_id="t9", completed=False, failed=False, interrupted=False,
           turn_exit_reason="max_iterations_reached(24/24)", model="m", platform="telegram")


def test_ledger_is_the_newest_todo_result():
    old = _todo_msg(["pending"]); new = _todo_msg(["completed"])
    led = receipts.ledger_from_history([old, {"role": "assistant", "content": "x"}, new])
    assert [t["status"] for t in led["todos"]] == ["completed"]
    assert receipts.ledger_from_history([{"role": "tool", "content": "not json"}]) is None
    assert receipts.ledger_from_history([{"role": "user", "content": '{"todos": []}'}]) is None   # only tool results count


def test_turn_choice_and_scope():
    assert receipts.turn_choice(None) == "no_ledger"
    assert receipts.turn_choice(receipts.ledger_from_history([_todo_msg(["completed", "cancelled"])])) == "complete"
    assert receipts.turn_choice(receipts.ledger_from_history([_todo_msg(["completed", "pending"])])) == "incomplete"
    assert receipts.turn_wanted("max_iterations_reached(24/24)", "exhausted")
    assert not receipts.turn_wanted("text_response(stop)", "exhausted")
    assert receipts.turn_wanted("text_response(stop)", "all")
    assert not receipts.turn_wanted("max_iterations_reached(24/24)", "off")


def test_turn_receipt_commits_to_the_open_ledger_and_leaks_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("INVINOVERITAS_API_KEY", "ivv_test")
    sent = []
    hooks, out = _load_plugin(tmp_path, monkeypatch, lambda url, key, body, t: sent.append(body) or
                              {"event": {"id": "ev2"}, "receipt": {}, "reveal": {"salt": "s2"}})
    assert hooks["post_llm_call"](session_id="s1", turn_id="t9", assistant_response="Status: all stages handled.",
                                  conversation_history=HISTORY) is None
    assert hooks["on_session_end"](**END) is None
    for t in threading.enumerate():
        if t.name == "invinoveritas-turn-receipt":
            t.join(5)
    assert len(sent) == 1 and sent[0]["choice"] == "incomplete" and sent[0]["options"] == receipts.TURN_OPTIONS
    wire = receipts.canonical(sent[0]).decode()
    assert "stage" not in wire and "all stages handled" not in wire        # only the salted hash leaves
    rec = json.loads(out.read_text().strip())
    c = rec["context"]
    assert rec["kind"] == "turn_end" and c["open_obligations"] == 9 and c["total_obligations"] == 11
    assert c["final_response_sha256"] == hashlib.sha256(b"Status: all stages handled.").hexdigest()
    assert hashlib.sha256(receipts.canonical(c)).hexdigest() == rec["context_sha256"] == sent[0]["context_sha256"]


def test_normal_turns_issue_nothing_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("INVINOVERITAS_API_KEY", "ivv_test")
    sent = []
    hooks, _ = _load_plugin(tmp_path, monkeypatch, lambda *a: sent.append(a) or {})
    hooks["post_llm_call"](session_id="s1", turn_id="t1", assistant_response="done", conversation_history=HISTORY)
    hooks["on_session_end"](**dict(END, turn_id="t1", turn_exit_reason="text_response(stop)", completed=True))
    for t in threading.enumerate():
        if t.name == "invinoveritas-turn-receipt":
            t.join(5)
    assert sent == []
