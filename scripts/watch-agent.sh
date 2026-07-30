#!/usr/bin/env bash
# Живой поток работы агента — то, что ZeroClaw пишет в свой журнал, а не в
# терминал.
#
# `zeroclaw daemon` показывает в stdout только баннер: события идут в
# `runtime-trace.jsonl`, и `--log-level` управляет их уровнем в файле, а не
# выводом на экран. Поэтому окно демона выглядит мёртвым, хотя внутри всё
# работает — этот скрипт и есть то самое окно, которое видно.
#
# Показывает шесть событий, из которых состоит один обмен: сообщение пришло,
# началась работа модели, вызвался инструмент, вернулся результат, ответ
# сформирован, ответ доставлен. Транспортный шум (переиспользование соединений
# с api.telegram.org и прочее) отбрасывается — из него в кадре ничего не читается.
#
#   ./scripts/watch-agent.sh
#
set -euo pipefail

TRACE="${ZEROCLAW_TRACE:-$HOME/.zeroclaw/data/state/runtime-trace.jsonl}"

if [[ ! -f "$TRACE" ]]; then
    echo "нет журнала: $TRACE" >&2
    echo "запусти сначала: zeroclaw daemon" >&2
    exit 1
fi

echo "agent activity — $TRACE"
echo

tail -n 0 -F "$TRACE" 2>/dev/null | python3 -u -c '
import json, sys

# Что показываем и как это назвать по-человечески. Порядок словаря — порядок
# одного обмена, так что в кадре видно ход, а не набор строк.
INTERESTING = {
    "channel inbound message":  ("← message received",  "\033[36m"),
    "processing inbound message": ("  processing",       "\033[90m"),
    "starting LLM call":        ("  thinking",           "\033[90m"),
    "tool_call_start":          ("  → tool call",        "\033[33m"),
    "tool_call_result":         ("  ← tool result",      "\033[33m"),
    "turn_final_response":      ("  answer composed",    "\033[90m"),
    "reply delivered":          ("→ reply delivered",    "\033[32m"),
}
RESET = "\033[0m"

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
    except Exception:
        continue
    msg = str(d.get("message", ""))
    hit = INTERESTING.get(msg)
    if hit is None:
        continue
    label, colour = hit
    ts = str(d.get("@timestamp", ""))[11:19]   # только время, дата в кадре ни к чему
    attrs = d.get("attributes") or {}
    extra = ""
    # У вызова инструмента показываем имя: это единственное поле, по которому в
    # кадре видно, что агент правда пошёл в наш сервер, а не просто поговорил.
    if isinstance(attrs, dict) and attrs.get("tool"):
        extra = f"  {attrs['tool']}"
    print(f"{colour}{ts}  {label}{extra}{RESET}")
'
