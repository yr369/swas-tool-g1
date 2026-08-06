"""
routers/ - one APIRouter module per area of the API (projects, scope,
findings, scanning, reports, health, live/websocket), included into the
app in main.py. Split out of the former monolithic main.py (batch:
main.py split). No re-exports here deliberately - main.py imports each
submodule by name (`from .routers import projects, scope, ...`) and
uses `<name>.router`, so there's nothing this __init__.py needs to
expose.
"""
