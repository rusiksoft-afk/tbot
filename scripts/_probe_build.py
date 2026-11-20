"""ВРЕМЕННЫЙ скрипт CI-диагностики: печатает, что осталось в поле build разобранного состава."""

import json
import sys

model = json.load(sys.stdin)
build = model["services"]["web"].get("build")
print("build=None" if build is None else "build=" + json.dumps(build, ensure_ascii=False)[:200])
