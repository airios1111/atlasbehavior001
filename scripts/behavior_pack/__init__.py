"""Behavior pack specs (144 behaviors). Rendered by scripts/gen_behavior_pack.py."""

from .gaps import SPECS as _GAPS
from .llm import SPECS as _LLM
from .ml import SPECS as _ML
from .ops import SPECS as _OPS
from .tactics import SPECS as _TACTICS

SPECS = [*_LLM, *_ML, *_OPS, *_TACTICS, *_GAPS]
