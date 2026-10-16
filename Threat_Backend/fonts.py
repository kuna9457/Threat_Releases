"""
fonts.py — Loads the bundled Mulish typeface at runtime.

The font is registered with Windows GDI for this process only (no system
install required), so the packaged .exe looks consistent everywhere,
including machines where Mulish isn't installed. If loading fails for any
reason (non-Windows, missing file, locked-down environment) the app falls
back to Segoe UI automatically — nothing breaks either way.
"""

import ctypes
import os
import sys
import tkinter.font as tkfont

FONT_FAMILY_PRIMARY = "Mulish"
FONT_FAMILY_FALLBACK = "Segoe UI"

_loaded = False


def _asset_path(*parts) -> str:
    # PyInstaller unpacks bundled data files under sys._MEIPASS at runtime.
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, "assets", "fonts", *parts)


def load_custom_fonts() -> None:
    """Registers assets/fonts/*.ttf with the OS. Safe to call multiple times."""
    global _loaded
    if _loaded:
        return
    _loaded = True

    if sys.platform != "win32":
        return

    FR_PRIVATE = 0x10
    for name in ("Mulish.ttf",):
        path = _asset_path(name)
        if os.path.exists(path):
            try:
                ctypes.windll.gdi32.AddFontResourceExW(path, FR_PRIVATE, 0)
            except Exception:
                pass


def resolve_family(root=None) -> str:
    """Returns 'Mulish' if Tk can actually see it, else the Segoe UI fallback."""
    try:
        families = set(tkfont.families(root))
    except Exception:
        return FONT_FAMILY_FALLBACK
    return FONT_FAMILY_PRIMARY if FONT_FAMILY_PRIMARY in families else FONT_FAMILY_FALLBACK
