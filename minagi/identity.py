#!/usr/bin/env python3
"""App identity for WhiteHat_mini-AGI.

Single source of truth for the app's display name and its derived
identifiers. `serve.py` renders it into the web UI title and header,
`train.py` prints it in run banners, and any future packaging metadata
imports it from here instead of hard-coding a second copy.
"""

APP_NAME = "WhiteHat_mini-AGI"
APP_TAGLINE = (
    "a continually learning byte-level model - "
    "hardened end to end: skills gated on the way in, "
    "output scanned on the way out"
)


def banner() -> str:
    """One-line identity string for CLI banners and log headers."""
    return f"{APP_NAME} - {APP_TAGLINE}"


if __name__ == "__main__":
    print(banner())
