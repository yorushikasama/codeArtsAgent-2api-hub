"""Regression tests for the tool_choice="none" do-it-forever loop.

Reported symptom: with deepseek-v4.1-flash driving an agent client, the model
kept replying "I'll do it" without ever emitting a tool call, appending two
messages per turn until the context reached ~297k tokens and the user had to
abort the request by hand (usage.jsonl recorded outcome=client_aborted,
gen_ms=128262, usage_missing=true).

Root cause: the WorkBuddy-path normalizer deleted the whole `tools` declaration
when the client sent tool_choice="none" (model degraded calls to text, looped
forever); its object-form downgrade also stopped the upstream's 11101 on the
official OpenAI spelling {"type":"none"}. That path retired with
build_upstream_body, so both protections now live in ca_codearts.chat_body /
normalize_tool_choice_value (ported 2026-10-25). These tests pin the live shape.
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _isolated_dirs import isolated_data_dirs  # noqa: E402  (its own data root)
# Its own directories, removed when this process exits. This suite used to share
# tests/_acc and tests/_use with _test_custom_tools.py, which made the two unsafe
# to run at the same time and left directories in the repo after a run.
_TMP = isolated_data_dirs("wb-tool-choice-")

import ca_codearts as CC
import ca_protocol as Q

PASS = FAIL = 0
def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1; print("  [PASS] " + label)
    else:
        FAIL += 1; print("  [FAIL] " + label + ("  " + str(extra) if extra else ""))

TOOLS = [{
    "type": "function",
    "function": {
        "name": "run_shell",
        "description": "Run a shell command",
        "parameters": {"type": "object",
                       "properties": {"command": {"type": "string"}},
                       "required": ["command"]},
    },
}]

def norm(tool_choice):
    tools = json.loads(json.dumps(TOOLS))
    body = CC.chat_body("deepseek-v4.1-flash", [], tools=tools,
                        tool_choice=tool_choice)
    return body

print("[1] tool_choice='none' must NOT delete the tools declaration")
o = norm("none")
check("tools survive", "tools" in o and len(o["tools"]) == 1, o.get("tools"))
check("function name intact", o["tools"][0]["function"]["name"] == "run_shell")
check("tool_choice kept as the string upstream accepts",
      o.get("tool_choice") == "none", o.get("tool_choice"))

print()
print("[2] upstream declares tool_choice as a string; an object form 11101s")
o = norm({"type": "none"})
check("object form downgraded to string", o.get("tool_choice") == "none", o.get("tool_choice"))
check("tools still present", "tools" in o)
check("tool_choice is never a dict",
      not isinstance(o.get("tool_choice"), dict), o.get("tool_choice"))

print()
print("[3] the other spellings keep working")
check("'auto' passes through", norm("auto").get("tool_choice") == "auto")
check("{type:auto} normalises to 'auto'",
      norm({"type": "auto"}).get("tool_choice") == "auto")
check("'required' passes through", norm("required").get("tool_choice") == "required")
named = norm({"type": "function", "function": {"name": "run_shell"}})
check("named function choice becomes the bare name",
      named.get("tool_choice") == "run_shell", named.get("tool_choice"))
check("named choice keeps tools", "tools" in named)

print()
print("[4] 缺省时按官方形状补 auto（2026-10-24 kernel 日志实证）")
o = norm(None)
check("tool_choice defaults to auto", o.get("tool_choice") == "auto", o.get("tool_choice"))
check("tools untouched", len(o["tools"]) == 1)

print()
print("[5] chat_body keeps tools end to end under tool_choice=none")
body = CC.chat_body("deepseek-v4.1-flash",
                    [{"role": "user", "content": "do the thing"}],
                    tools=json.loads(json.dumps(TOOLS)),
                    tool_choice="none")
check("full pipeline retains tools", bool(body.get("tools")), body.get("tools"))
check("full pipeline keeps a string tool_choice",
      body.get("tool_choice") == "none", body.get("tool_choice"))

print()
print("[6] DSML text fallback still parses upstream's real full-width syntax")
FS = "\uff5c\uff5c"
block = (
    "<" + FS + "DSML" + FS + " calls>" + chr(10) +
    "<" + FS + "DSML" + FS + ' invoke name="run_shell">' + chr(10) +
    "<" + FS + "DSML" + FS + ' parameter name="command" string="true">ls -l' +
    "</" + FS + "DSML" + FS + " parameter>" + chr(10) +
    "</" + FS + "DSML" + FS + " invoke>" + chr(10) +
    "</" + FS + "DSML" + FS + " calls>"
)
calls, clean = Q.parse_dsml_tool_calls(block)
check("DSML call recovered from text", bool(calls), calls)
if calls:
    check("recovered the function name", calls[0]["name"] == "run_shell", calls[0])
    check("recovered the arguments",
          json.loads(calls[0]["arguments"]).get("command") == "ls -l", calls[0])
check("DSML tags stripped from visible text", "DSML" not in clean, repr(clean[:80]))

print()
print("SUMMARY: PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
