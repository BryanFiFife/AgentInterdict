from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memoryguard import db

db.init_db()
print(db.backup_database("cli"))
