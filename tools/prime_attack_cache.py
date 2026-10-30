#!/usr/bin/env python3
"""Fill pySigma's ATT&CK cache from the pinned extract (see dac_common.prime_pysigma_attack_cache)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dac_common import ATTACK_VERSION, prime_pysigma_attack_cache  # noqa: E402

prime_pysigma_attack_cache()
print(f"pySigma ATT&CK cache primed with pinned Enterprise ATT&CK v{ATTACK_VERSION}")
