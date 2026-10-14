from pathlib import Path

import pytest

from requirements_review import load_json, validate_review


@pytest.fixture
def requirements():
    return load_json(
        Path(__file__).resolve().parent / "requirements.json"
    )["requirements"]


def valid_review(requirements):
    return {
        "overall_status": "PASS",
        "results": [
            {
                "requirement_id": requirement["id"],
                "status": "SATISFIED",
                "evidence": "Supporting evidence supplied for testing.",
                "explanation": "The requirement is marked satisfied.",
            }
            for requirement in requirements
        ],
        "blocking_gaps": [],
    }


def test_valid_review_passes(requirements):
    result = valid_review(requirements)

    validate_review(result, requirements)


def test_missing_requirement_is_rejected(requirements):
    result = valid_review(requirements)
    result["results"].pop()

    with pytest.raises(ValueError):
        validate_review(result, requirements)


def test_duplicate_requirement_id_is_rejected(requirements):
    result = valid_review(requirements)
    result["results"][1]["requirement_id"] = (
        result["results"][0]["requirement_id"]
    )

    with pytest.raises(ValueError):
        validate_review(result, requirements)


def test_unsatisfied_blocker_cannot_pass(requirements):
    result = valid_review(requirements)
    result["results"][0]["status"] = "GAP"

    with pytest.raises(ValueError):
        validate_review(result, requirements)


def test_invalid_status_is_rejected(requirements):
    result = valid_review(requirements)
    result["results"][0]["status"] = "MAYBE"

    with pytest.raises(ValueError):
        validate_review(result, requirements)
