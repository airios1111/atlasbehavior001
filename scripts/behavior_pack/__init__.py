"""Behavior pack specs (131 behaviors). Rendered by scripts/gen_behavior_pack.py."""

from .llm import SPECS as _LLM
from .ml import SPECS as _ML
from .ops import SPECS as _OPS
from .provenance import SPECS as _PROVENANCE  # draws nothing from the shared seeded RNG
from .tactics import SPECS as _TACTICS

SPECS = [*_LLM, *_ML, *_OPS, *_TACTICS, *_PROVENANCE]
