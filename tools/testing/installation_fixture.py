"""Explicit installation identity for the historical offline test fixtures.

These suites model the compatibility installation with synthetic host state.
Selecting that identity is a test setup choice, never a production fallback.
Cold-start identity tests load independent modules or isolated interpreters;
they must supply their own protected identity files and do not inherit this
selection. Nothing is written to the executing machine's /etc directory.
"""
import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]


def _select_legacy(name, source):
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    module.select(module.Installation.legacy())


def select_legacy():
    # Isolated restart drivers use -I and cannot inherit PYTHONPATH. Bind their
    # synthetic application import to this checkout, not another editable venv.
    sys.path.insert(0, str(ROOT / 'plugins/whatsapp'))
    if 'installation_layout' not in sys.modules:
        _select_legacy('installation_layout', ROOT / 'plugins/whatsapp/scripts/installation_layout.py')
    else:
        layout = sys.modules['installation_layout']
        if Path(layout.__file__).resolve() != ROOT / 'plugins/whatsapp/scripts/installation_layout.py':
            raise AssertionError('Offline WhatsApp harness loaded a foreign installation layout')
        layout.select(layout.Installation.legacy())

    # Package imports use distinct copies of the same reviewed identity contract.
    from sally_whatsapp import installation as application_installation
    from host import installation as host_installation
    application_installation.select(application_installation.Installation.legacy())
    host_installation.select(host_installation.Installation.legacy())
