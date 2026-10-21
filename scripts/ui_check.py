"""Load the desk in headless Chromium, click through the demo story, and take screenshots.

    python scripts/ui_check.py --url http://127.0.0.1:8000 --out ui-shots

Runs in CI (playwright + chromium), never needed locally. Fails on a JavaScript error, a
failed API call, a citation chip that does not light its evidence, or horizontal scroll at
a 390 px phone width.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--out", default="ui-shots")
    args = ap.parse_args()
    from playwright.sync_api import sync_playwright

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    with sync_playwright() as p:
        br = p.chromium.launch()
        for scheme in ("light", "dark"):
            # bypass_csp only lets the test's own wait_for_function run; the app's CSP is checked by test_api
            pg = br.new_context(viewport={"width": 1440, "height": 900}, color_scheme=scheme,
                                bypass_csp=True).new_page()
            pg.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
            pg.on("console", lambda m: errors.append(f"console: {m.text}") if m.type == "error"
                  and "fonts.g" not in m.text else None)
            pg.on("response", lambda r: errors.append(f"HTTP {r.status} {r.url}")
                  if "/api/" in r.url and r.status >= 400 else None)
            pg.goto(args.url)
            pg.wait_for_selector(".rows li")
            pg.screenshot(path=out / f"01_queue_{scheme}.png")
            pg.click("#batch")
            pg.wait_for_function("document.querySelector('#tally').textContent.includes('not read yet') && "
                                 "!document.querySelector('#batch').disabled")
            pg.click("[data-tab=escalated]")
            pg.wait_for_selector("[data-tab=escalated].on")
            pg.wait_for_selector(".rows li button .pill.ESCALATED")
            pg.click(".rows li button")
            pg.wait_for_selector(".memo .cite")
            cite = pg.locator(".memo .cite").nth(1)
            rid = cite.get_attribute("data-rid")
            cite.click()
            if pg.locator(f".step.lit[data-rid='{rid}']").count() != 1:
                errors.append("citation chip did not light its evidence")
            pg.screenshot(path=out / f"02_escalated_case_{scheme}.png", full_page=True)
            if scheme == "light":
                # the desk's order puts attacks first; arrival order has cases that need a person
                pg.select_option("#order", "arrival")
                pg.wait_for_timeout(500)
                pg.click("#batch")
                pg.wait_for_function("!document.querySelector('#batch').disabled")
                pg.click("[data-tab=needs_you]")
                pg.wait_for_selector("[data-tab=needs_you].on")
                pg.wait_for_selector(".rows li button .pill.HUMAN")
                cid = pg.locator(".rows li button").first.get_attribute("data-case")
                pg.click(f".rows li button[data-case='{cid}']")
                pg.wait_for_selector(f".case-head h2:text-is('{cid}')")
                pg.wait_for_selector("#lab")
                pg.select_option("#lab", "benign")
                pg.click("#override")
                pg.wait_for_selector(".labelled")
                if "benign" not in pg.locator(".labelled").inner_text():
                    errors.append("the saved label is not the one chosen")
                pg.screenshot(path=out / "03_labelled.png", full_page=True)
                for view in ("results", "audit", "about"):
                    pg.click(f"[data-view={view}]")
                    pg.wait_for_timeout(600)
                    pg.screenshot(path=out / f"04_{view}.png", full_page=True)
                    if view == "audit" and "intact" not in pg.locator("#view-audit").inner_text():
                        errors.append("audit chain not shown as intact")
            pg.close()
        ph = br.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2,
                            bypass_csp=True).new_page()
        ph.on("pageerror", lambda e: errors.append(f"pageerror (phone): {e}"))
        ph.goto(args.url)
        ph.wait_for_selector(".rows li")
        ph.click(".rows li button")
        ph.wait_for_timeout(500)
        wide = ph.evaluate("document.documentElement.scrollWidth > window.innerWidth + 1")
        if wide:
            errors.append("horizontal scroll at 390 px")
        ph.screenshot(path=out / "05_phone.png", full_page=True)
        ph.click("[data-view=results]")
        ph.wait_for_timeout(600)
        if ph.evaluate("document.documentElement.scrollWidth > window.innerWidth + 1"):
            errors.append("horizontal scroll at 390 px on results")
        ph.screenshot(path=out / "06_phone_results.png", full_page=True)
        br.close()
    for e in errors:
        print("UI PROBLEM:", e)
    print(f"screenshots in {out}/; {len(errors)} problems")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
