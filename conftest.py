"""Bind explicit compatibility identity only for the WhatsApp test checkout."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
if (ROOT / 'plugins/whatsapp').is_dir():
    from tools.testing.installation_fixture import select_legacy
    select_legacy()
