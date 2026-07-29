"""
screenshots.py - opt-in visual capture of live hosts for quick triage.

Plain-language: sometimes the fastest way to tell if a host is worth
digging into is to just LOOK at it - a default nginx page, a login
screen, an admin panel, a "site under construction" placeholder all
tell you something in half a second that reading raw httpx output
doesn't. This grabs one screenshot per live host during probe.

Same opt-in shape as verify.py's headless-browser XSS proof: if
Playwright (and its Chromium browser) isn't installed, this silently
does nothing rather than failing the scan - screenshots are a nice-to-
have, never a blocker. Enabling it means adding Chromium to the backend
image, which has a real size cost on the ARM64 build (same tradeoff
already documented for the Playwright XSS-proof feature) - verify the
image size increase is acceptable on your box before enabling in
production, this hasn't been tested against the actual ARM64 build.
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger("swas.screenshots")

SCREENSHOT_DIR = Path(os.environ.get("SCREENSHOT_DIR", "/data/scans/screenshots"))


def is_enabled() -> bool:
    return os.environ.get("SCREENSHOT_ENABLED", "false").lower() in ("1", "true", "yes")


def screenshot_path(target_id: int) -> Path:
    return SCREENSHOT_DIR / f"{target_id}.png"


async def capture(target_id: int, url: str) -> bool:
    """
    Saves one screenshot for this target, overwriting any previous one
    (screenshots reflect current state, not history - the diff/
    chronology features already cover "what changed over time" for
    findings; screenshots are a snapshot, not a timeline). Returns True
    on success, False on any failure (Playwright missing, browser
    launch failure, page load timeout, etc.) - callers should treat
    False as "no screenshot available", not raise on it.
    """
    if not is_enabled():
        return False
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.info("screenshots: playwright not installed - skipping capture for target_id=%s", target_id)
        return False

    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    dest = screenshot_path(target_id)

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page(viewport={"width": 1280, "height": 800})
            try:
                await page.goto(url, timeout=10000, wait_until="domcontentloaded")
                await page.wait_for_timeout(800)  # let obvious above-the-fold content settle
                await page.screenshot(path=str(dest))
            except Exception as exc:  # noqa: BLE001 - page load can fail many ways, all mean "skip this one"
                logger.info("screenshots: capture failed for %s: %s", url, exc)
                await browser.close()
                return False
            await browser.close()
        return True
    except Exception as exc:  # noqa: BLE001 - Playwright/browser install issues, treat as unavailable
        logger.info("screenshots: browser session failed: %s", exc)
        return False
