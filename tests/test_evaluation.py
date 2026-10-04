from intentshield.evaluation import build_cases, dataset_hash, run_evaluation, wilson


def test_dataset_is_deterministic_and_labelled():
    assert dataset_hash(build_cases()) == dataset_hash(build_cases())
    labels = {c.label for c in build_cases()}
    assert labels == {"attack", "benign"}
    assert len({c.id for c in build_cases()}) == len(build_cases())


def test_wilson_interval_bounds():
    low, high = wilson(0, 80)
    assert low == 0.0 and 0 < high < 0.06
    assert wilson(0, 0) == (0.0, 0.0)


def test_safety_invariants_hold_in_the_harness():
    report = run_evaluation()
    by_name = {r["defense"]: r for r in report["results"]}
    assert by_name["no_defense"]["attack_success_rate"]["rate"] == 1.0
    shield = by_name["intentshield"]
    # No attack may reach an unreviewed ALLOW, and benign calls must not be refused.
    assert shield["attack_success_rate"]["rate"] == 0.0
    assert shield["benign_false_block_rate"]["rate"] == 0.0
    assert shield["benign_decisions"]["BLOCK"] == 0
    assert shield["attack_success_rate"]["rate"] < by_name["keyword_filter"]["attack_success_rate"]["rate"]
