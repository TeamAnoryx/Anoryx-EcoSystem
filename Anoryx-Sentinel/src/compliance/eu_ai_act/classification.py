"""EU AI Act risk-classification decision support (F-030, ADR-0036).

Screens a described AI use-case against the EU AI Act's risk tiers:
  - Article 5 PROHIBITED practices (unacceptable risk),
  - Annex III HIGH-RISK use-case categories,
  - otherwise limited/minimal risk (with the Article 50 transparency note).

CRITICAL: this is DECISION SUPPORT, NOT LEGAL ADVICE and NOT a conformity
assessment. It flags likely tiers from a controlled vocabulary of use-case
tags so an operator can route the case to the right obligations and to counsel.
The definitive classification is a legal determination the operator must make.
Honest-language rule: "likely high-risk", never "compliant"/"is high-risk".
"""

from __future__ import annotations

from dataclasses import dataclass, field

DISCLAIMER = (
    "Decision support only — NOT legal advice and NOT a conformity assessment. "
    "The definitive EU AI Act risk classification is a legal determination for "
    "the provider/deployer and their counsel."
)

# Article 5 — prohibited practices (unacceptable risk). Controlled tags.
_PROHIBITED: dict[str, str] = {
    "social_scoring": "Art.5(1)(c) social scoring by public/private actors",
    "subliminal_manipulation": "Art.5(1)(a) subliminal/manipulative techniques causing harm",
    "exploit_vulnerabilities": "Art.5(1)(b) exploiting vulnerabilities of specific groups",
    "biometric_categorisation_sensitive": "Art.5(1)(g) biometric categorisation by sensitive trait",
    "untargeted_facial_scraping": "Art.5(1)(e) untargeted scraping to build facial-recognition DB",
    "emotion_recognition_workplace": "Art.5(1)(f) emotion recognition in workplace/education",
    "realtime_remote_biometric_public": "Art.5(1)(h) real-time remote biometric ID in public space",
    "predictive_policing_individual": "Art.5(1)(d) individual predictive policing on profiling",
}

# Annex III — high-risk use-case categories. Controlled tags.
_HIGH_RISK: dict[str, str] = {
    "biometrics": "Annex III(1) biometric identification/categorisation",
    "critical_infrastructure": "Annex III(2) safety components of critical infrastructure",
    "education": "Annex III(3) education and vocational training (access, evaluation)",
    "employment": "Annex III(4) employment, worker management, access to self-employment",
    "essential_services": "Annex III(5) access to essential private/public services & benefits",
    "creditworthiness": "Annex III(5)(b) credit scoring / creditworthiness evaluation",
    "law_enforcement": "Annex III(6) law enforcement",
    "migration_asylum_border": "Annex III(7) migration, asylum, border-control management",
    "justice_democracy": "Annex III(8) administration of justice and democratic processes",
    "insurance_risk_pricing": "Annex III(5)(c) risk assessment/pricing in life & health insurance",
}


@dataclass(frozen=True)
class ClassificationResult:
    """Screening outcome for a described AI use-case."""

    tier: str  # "prohibited" | "high_risk" | "limited_or_minimal"
    matched_prohibited: tuple[str, ...] = ()
    matched_high_risk: tuple[str, ...] = ()
    obligations_hint: tuple[str, ...] = field(default_factory=tuple)
    notes: tuple[str, ...] = ()
    disclaimer: str = DISCLAIMER


def known_prohibited_tags() -> tuple[str, ...]:
    return tuple(sorted(_PROHIBITED))


def known_high_risk_tags() -> tuple[str, ...]:
    return tuple(sorted(_HIGH_RISK))


def classify(use_case_tags: list[str]) -> ClassificationResult:
    """Screen a list of controlled use-case tags into a likely EU AI Act tier.

    Unknown tags are ignored (not an error) but noted. Prohibited beats
    high-risk beats limited/minimal.
    """
    normalized = [t.strip().lower() for t in use_case_tags if t and t.strip()]
    prohibited = tuple(_PROHIBITED[t] for t in normalized if t in _PROHIBITED)
    high_risk = tuple(_HIGH_RISK[t] for t in normalized if t in _HIGH_RISK)
    unknown = tuple(t for t in normalized if t not in _PROHIBITED and t not in _HIGH_RISK)

    notes: list[str] = []
    if unknown:
        notes.append(f"unrecognised tags ignored (not classified): {sorted(set(unknown))}")

    if prohibited:
        return ClassificationResult(
            tier="prohibited",
            matched_prohibited=prohibited,
            matched_high_risk=high_risk,
            obligations_hint=(
                "Likely PROHIBITED under Article 5 — the practice may not be placed on "
                "the market or put into service. Seek legal counsel immediately.",
            ),
            notes=tuple(notes),
        )

    if high_risk:
        return ClassificationResult(
            tier="high_risk",
            matched_high_risk=high_risk,
            obligations_hint=(
                "Likely HIGH-RISK (Annex III) — Chapter III Section 2 obligations apply: "
                "risk management (Art.9), data governance (Art.10), technical documentation "
                "(Art.11), record-keeping/logging (Art.12), transparency to deployers "
                "(Art.13), human oversight (Art.14), accuracy/robustness/cybersecurity "
                "(Art.15), and conformity assessment (Art.43) before market placement.",
                "Sentinel supplies technical evidence for Art.12 (logging) and Art.15 "
                "(robustness/cybersecurity); run `sentinel-cli compliance evidence "
                "--framework EU_AI_ACT` for the current coverage.",
            ),
            notes=tuple(notes),
        )

    return ClassificationResult(
        tier="limited_or_minimal",
        obligations_hint=(
            "No prohibited or Annex III high-risk tag matched. Limited-risk systems may "
            "still carry Article 50 transparency duties (disclose AI interaction, mark "
            "synthetic content). Re-screen if the use-case changes.",
        ),
        notes=tuple(notes),
    )
