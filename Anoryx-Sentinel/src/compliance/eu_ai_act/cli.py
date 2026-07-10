"""sentinel-euaiact — operator CLI for the F-030 EU AI Act module (ADR-0036).

    sentinel-euaiact classify --tags employment,biometrics
    sentinel-euaiact list-tags
    sentinel-euaiact disclosure --system "Foo" --provider "Acme" [--purpose "..."] [--json]

classify screens controlled use-case tags into a likely EU AI Act risk tier
(decision support, NOT legal advice). disclosure generates an Article 13
instructions-for-use TEMPLATE. The EU AI Act framework's per-control evidence is
available via `sentinel-cli compliance evidence --framework EU_AI_ACT`.
"""

from __future__ import annotations

import argparse
import json
import sys

import structlog

log = structlog.get_logger(__name__)


def _cmd_classify(tags_csv: str, as_json: bool) -> int:
    from compliance.eu_ai_act.classification import classify

    tags = [t for t in tags_csv.split(",") if t.strip()]
    result = classify(tags)
    if as_json:
        payload = {
            "tier": result.tier,
            "matched_prohibited": list(result.matched_prohibited),
            "matched_high_risk": list(result.matched_high_risk),
            "obligations_hint": list(result.obligations_hint),
            "notes": list(result.notes),
            "disclaimer": result.disclaimer,
        }
        print(json.dumps(payload, indent=2))
        return 0
    print(f"Likely tier: {result.tier.upper()}")
    if result.matched_prohibited:
        print("Prohibited-practice matches (Art.5):")
        for m in result.matched_prohibited:
            print(f"  - {m}")
    if result.matched_high_risk:
        print("High-risk matches (Annex III):")
        for m in result.matched_high_risk:
            print(f"  - {m}")
    for hint in result.obligations_hint:
        print(f"\n{hint}")
    for note in result.notes:
        print(f"\nnote: {note}")
    print(f"\nDISCLAIMER: {result.disclaimer}")
    return 0


def _cmd_list_tags() -> int:
    from compliance.eu_ai_act.classification import known_high_risk_tags, known_prohibited_tags

    print("Prohibited-practice tags (Art.5):")
    for t in known_prohibited_tags():
        print(f"  {t}")
    print("\nHigh-risk tags (Annex III):")
    for t in known_high_risk_tags():
        print(f"  {t}")
    return 0


def _cmd_disclosure(
    system: str, provider: str, purpose: str | None, as_json: bool, out: str | None
) -> int:
    from compliance.eu_ai_act.disclosure import build_disclosure, render_disclosure_markdown

    doc = build_disclosure(system_name=system, provider_name=provider, intended_purpose=purpose)
    rendered = json.dumps(doc, indent=2) if as_json else render_disclosure_markdown(doc)
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print(f"wrote Article 13 disclosure template to {out}")
    else:
        print(rendered)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-euaiact", description="Anoryx Sentinel EU AI Act module CLI (F-030)."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    clf = sub.add_parser("classify", help="Screen use-case tags into a likely risk tier.")
    clf.add_argument("--tags", required=True, help="Comma-separated controlled use-case tags.")
    clf.add_argument("--json", action="store_true", dest="as_json")

    sub.add_parser("list-tags", help="List the controlled prohibited/high-risk tags.")

    dsc = sub.add_parser("disclosure", help="Generate an Article 13 instructions-for-use template.")
    dsc.add_argument("--system", required=True, help="AI system name.")
    dsc.add_argument("--provider", required=True, help="Provider name.")
    dsc.add_argument("--purpose", default=None, help="Intended purpose (optional).")
    dsc.add_argument("--json", action="store_true", dest="as_json")
    dsc.add_argument("--out", default=None, help="Write to a file instead of stdout.")

    args = parser.parse_args(argv)

    if args.cmd == "classify":
        return _cmd_classify(args.tags, args.as_json)
    if args.cmd == "list-tags":
        return _cmd_list_tags()
    if args.cmd == "disclosure":
        return _cmd_disclosure(args.system, args.provider, args.purpose, args.as_json, args.out)
    parser.error("unknown command")  # pragma: no cover
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
