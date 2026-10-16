#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "six==1.17.0",
#     "certifi",
# ]
# [tool.uv]
# exclude-newer = "2026-10-01T00:00:00Z"
# ///
import six
print(six.PY3)
