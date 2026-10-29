"""Behavior pack specs (100 behaviors). Rendered by scripts/gen_behavior_pack.py."""

from .llm import SPECS as _LLM
from .ml import SPECS as _ML
from .ops import SPECS as _OPS

SPECS = [*_LLM, *_ML, *_OPS]
