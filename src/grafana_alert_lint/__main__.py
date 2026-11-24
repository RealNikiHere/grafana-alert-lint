"""`python -m grafana_alert_lint` — тот же CLI, что и entry point `galint`."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
