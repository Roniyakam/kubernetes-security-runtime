import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("WEBHOOK_TOKEN", "test-token")
os.environ.setdefault("DRY_RUN", "true")
