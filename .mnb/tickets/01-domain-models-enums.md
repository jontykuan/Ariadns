# 01: Core Domain Models, Enums & Package Scaffold

**What to build:** Define canonical enums, dataclasses matching SRS 5.2 `result.json`, and `pyproject.toml` package scaffold for `ariadns`.
**Blocked by:** None (frontier)
**Target files:** `pyproject.toml`, `requirements.txt`, `src/ariadns/__init__.py`, `src/ariadns/models/__init__.py`, `src/ariadns/models/enums.py`, `src/ariadns/models/entities.py`, `tests/test_01_models.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given an `InvestigationResult` instance populated with `IdentityProfile`, `Infrastructure`, `SubdomainRecord`, `PivotResult`, and `L2Result`, When serialized via `.to_dict()`, Then the dictionary keys and types strictly match SRS Section 5.2 `result.json` schema.
- [ ] Given `OriginVerificationStatus`, `ConfidenceLevel`, and `ModuleStatus` enums, When accessed by string value, Then all canonical states defined in `.mnb/STANDARDS.md` exist.

## Deterministic Verification
- Unit test path: `tests/test_01_models.py`
- Mutation target: `src/ariadns/models/entities.py`
