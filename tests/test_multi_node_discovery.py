from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_independent_multi_node_discovery_exchange():
    repository = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(repository / "examples" / "multi_node_discovery_demo.py")],
        cwd=repository,
        capture_output=True,
        text=True,
        timeout=45,
        check=True,
    )
    assert "OIX Phase 16 independent multi-node exchange: PASS" in result.stdout
    assert "databases: 2 separate SQLite files" in result.stdout
    assert "discovery trust state: discovered_untrusted" in result.stdout
