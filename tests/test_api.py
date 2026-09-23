"""End-to-end tests against the FastAPI app with a temp SQLite database."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-")
    os.close(fd)
    os.remove(path)  # let sqlite create it
    db.reset_db(path)
    from app.main import app

    with TestClient(app) as c:
        yield c
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


# ---------------------------------------------------------------------------
def test_root_and_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert client.get("/").status_code == 200


def test_full_scenario_conflicts_and_shadowing(client: TestClient) -> None:
    body = {
        "name": "scenario-1",
        "rules": [
            {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100, "source_tag": "core"},
            {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200, "source_tag": "edge"},
            {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit", "priority": 50, "source_tag": "edge"},
            {"rule_id": "d", "cidr": "10.1.0.0/16", "action": "deny", "priority": 300, "source_tag": "dup"},
        ],
    }
    r = client.post("/api/analyze", json=body)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["persisted"] is True
    by_id = {rule["rule_id"]: rule for rule in data["rules"]}

    # a: /8 minus b's /16 (d is only a same-CIDR duplicate of b, not a separate child)
    a = by_id["a"]
    assert a["status"] == "partial"
    assert a["covered"] == 2 ** 24 - 2 ** 16

    # b deny vs a permit: effective except c's /24 -> partial, conflict
    b = by_id["b"]
    assert b["status"] == "partial"
    assert b["covered"] == 2 ** 16 - 2 ** 8
    assert b["has_conflict"] is True

    # c wins its own /24, conflicts with b
    c = by_id["c"]
    assert c["status"] == "active"
    assert c["effective_cidrs"] == ["10.1.1.0/24"]

    # d is an exact-prefix duplicate of b and same action -> shadowed, no conflict
    d = by_id["d"]
    assert d["role"] == "duplicate"
    assert d["status"] == "shadowed"
    assert d["covered"] == 0
    assert d["has_conflict"] is False

    # Minimal pairs: (b,a) and (c,b); transitive (c,a) is suppressed.
    pairs = {(p["rule_id"], p["other_rule_id"]) for p in data["minimal_conflict_pairs"]}
    assert pairs == {("b", "a"), ("c", "b")}
    ba = next(p for p in data["minimal_conflict_pairs"] if p["rule_id"] == "b")
    assert ba["winner_rule_id"] == "b"
    assert ba["kind"] == "cover"

    # Priority inversion: b (priority 200) overrides a (priority 100) by prefix length.
    inversions = [f for f in data["findings"] if f.get("priority_inversion")]
    assert {(f["rule_id"], f["other_rule_id"]) for f in inversions} == {("b", "a")}

    summary = data["summary"]
    assert summary["rule_count"] == 4
    assert summary["partial_rules"] == 2
    assert summary["shadowed_rules"] == 1
    assert summary["behavioral_conflicts"] == 2


def test_fully_shadowed_warning(client: TestClient) -> None:
    body = {
        "rules": [
            {"cidr": "192.168.0.0/24", "action": "permit"},
            {"cidr": "192.168.0.0/25", "action": "deny"},
            {"cidr": "192.168.0.128/25", "action": "deny"},
        ]
    }
    r = client.post("/api/analyze", json=body)
    assert r.status_code == 200
    data = r.json()
    root = next(rule for rule in data["rules"] if rule["cidr"] == "192.168.0.0/24")
    assert root["status"] == "shadowed"
    assert root["covered"] == 0
    assert any(f["type"] == "fully_shadow" and f["severity"] == "warning" for f in data["findings"])
    # Both halves agree with... root permit vs deny children -> two conflict pairs,
    # even though the parent itself covers nothing, the children are behavioural.
    assert len(data["minimal_conflict_pairs"]) == 2


def test_shadowed_child_same_action_produces_no_conflict_pair(client: TestClient) -> None:
    # r2 (deny /16) is fully shadowed by two deny /17s.  No conflict exists
    # *inside* the /16, but the /16 as a whole still denies against the
    # permit /8: the same-action run (r3/r4 -> r2) is jumped over and each
    # effective leaf pairs with r1; the fully shadowed r2 generates no pair.
    body = {
        "rules": [
            {"cidr": "10.0.0.0/8", "action": "permit", "priority": 100},
            {"cidr": "10.0.0.0/16", "action": "deny", "priority": 100},
            {"cidr": "10.0.0.0/17", "action": "deny", "priority": 100},
            {"cidr": "10.0.128.0/17", "action": "deny", "priority": 100},
        ]
    }
    data = client.post("/api/analyze", json=body).json()
    pairs = {(p["rule_id"], p["other_rule_id"]) for p in data["minimal_conflict_pairs"]}
    assert pairs == {("r3", "r1"), ("r4", "r1")}
    # Override ranges of the two leaves partition the whole /16.
    ranges = sorted(
        cidr for p in data["minimal_conflict_pairs"] for cidr in p["override_range"]
    )
    assert ranges == ["10.0.0.0/17", "10.0.128.0/17"]

    # The direct boundary edge r2 -> r1 is flagged behavioural even though r2
    # itself covers nothing; inner same-action edges are not.
    by_edge = {(f["rule_id"], f["other_rule_id"]): f for f in data["findings"] if f["type"] == "cover"}
    assert by_edge[("r2", "r1")]["behavioral"] is True
    assert by_edge[("r3", "r2")]["behavioral"] is False
    assert by_edge[("r4", "r2")]["behavioral"] is False

    # No same-action pair is ever reported.
    assert not any(p["action"] == p["other_action"] for p in data["minimal_conflict_pairs"])


def test_duplicate_cidr_action_conflict_pair(client: TestClient) -> None:
    body = {
        "rules": [
            {"cidr": "172.16.0.0/12", "action": "permit", "priority": 10},
            {"cidr": "172.16.0.0/12", "action": "deny", "priority": 20},
        ]
    }
    data = client.post("/api/analyze", json=body).json()
    assert len(data["minimal_conflict_pairs"]) == 1
    pair = data["minimal_conflict_pairs"][0]
    assert pair["kind"] == "duplicate"
    assert pair["rule_id"] == "r2"
    assert pair["winner_rule_id"] == "r1"
    assert pair["override_range"] == ["172.16.0.0/12"]


def test_ipv6_is_handled_independently(client: TestClient) -> None:
    body = {
        "rules": [
            {"cidr": "2001:db8::/32", "action": "deny"},
            {"cidr": "2001:db8:1::/48", "action": "permit"},
            {"cidr": "::1/128", "action": "permit"},
        ]
    }
    data = client.post("/api/analyze", json=body).json()
    assert data["summary"]["ipv6_rules"] == 3
    by_id = {r["rule_id"]: r for r in data["rules"]}
    assert by_id["r1"]["status"] == "partial"
    assert by_id["r2"]["status"] == "active"
    assert by_id["r3"]["status"] == "active"
    assert len(data["minimal_conflict_pairs"]) == 1


def test_invalid_inputs_return_400(client: TestClient) -> None:
    # Host bits set
    r = client.post("/api/analyze", json={"rules": [{"cidr": "10.0.0.5/24", "action": "permit"}]})
    assert r.status_code == 400
    assert "invalid CIDR" in r.json()["detail"]

    # Duplicate rule_id
    r = client.post(
        "/api/analyze",
        json={
            "rules": [
                {"rule_id": "x", "cidr": "10.0.0.0/24", "action": "permit"},
                {"rule_id": "x", "cidr": "10.1.0.0/24", "action": "permit"},
            ]
        },
    )
    assert r.status_code == 400
    assert "duplicate rule_id" in r.json()["detail"]

    # Empty rule list
    r = client.post("/api/analyze", json={"rules": []})
    assert r.status_code == 422

    # Bad action -> schema error
    r = client.post("/api/analyze", json={"rules": [{"cidr": "10.0.0.0/24", "action": "maybe"}]})
    assert r.status_code == 422


def test_idempotent_submission_and_versions(client: TestClient) -> None:
    body = {"rules": [{"cidr": "10.0.0.0/8", "action": "permit"}]}
    first = client.post("/api/analyze", json=body).json()
    second = client.post("/api/analyze", json=body).json()
    assert first["id"] == second["id"]
    assert first["ruleset_hash"] == second["ruleset_hash"]

    listing = client.get("/api/analyses").json()
    assert listing["total"] == 1

    fetched = client.get(f"/api/analyses/{first['id']}").json()
    assert fetched["ruleset_hash"] == first["ruleset_hash"]

    assert client.get("/api/analyses/does-not-exist").status_code == 404


def test_rules_and_findings_query_filters(client: TestClient) -> None:
    body = {
        "rules": [
            {"cidr": "10.0.0.0/8", "action": "permit"},
            {"cidr": "10.1.0.0/16", "action": "deny"},
            {"cidr": "2001:db8::/32", "action": "permit"},
        ]
    }
    aid = client.post("/api/analyze", json=body).json()["id"]

    partial = client.get(f"/api/analyses/{aid}/rules", params={"status": "partial"}).json()
    assert {r["rule_id"] for r in partial["rules"]} == {"r1"}

    deny = client.get(f"/api/analyses/{aid}/rules", params={"action": "deny"}).json()
    assert {r["rule_id"] for r in deny["rules"]} == {"r2"}

    v6 = client.get(f"/api/analyses/{aid}/rules", params={"ip": 6}).json()
    assert {r["rule_id"] for r in v6["rules"]} == {"r3"}

    conflicts = client.get(f"/api/analyses/{aid}/findings", params={"severity": "conflict"}).json()
    assert conflicts["count"] >= 1

    behavioral = client.get(f"/api/analyses/{aid}/findings", params={"behavioral_only": True}).json()
    assert all(f["behavioral"] for f in behavioral["findings"])


def test_export_json(client: TestClient) -> None:
    aid = client.post(
        "/api/analyze", json={"rules": [{"cidr": "10.0.0.0/8", "action": "permit"}]}
    ).json()["id"]
    r = client.get(f"/api/analyses/{aid}/export.json")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/json"
    assert f'attachment; filename="{aid}.json"' in r.headers["content-disposition"]
    payload = r.json()
    assert payload["id"] == aid
    assert "minimal_conflict_pairs" in payload


def test_save_false_is_not_persisted(client: TestClient) -> None:
    r = client.post(
        "/api/analyze",
        json={"rules": [{"cidr": "10.0.0.0/8", "action": "permit"}], "save": False},
    )
    assert r.json()["persisted"] is False
    assert client.get("/api/analyses").json()["total"] == 0


# ---------------------------------------------------------------------------
# Semantic diff between saved versions
# ---------------------------------------------------------------------------
def _submit(client: TestClient, rules: list[dict], name: str | None = None) -> str:
    return client.post("/api/analyze", json={"name": name, "rules": rules}).json()["id"]


def _diff(client: TestClient, base: str, target: str):
    return client.get("/api/analyses/diff", params={"base": base, "target": target})


def test_diff_basic_action_change_and_none(client: TestClient) -> None:
    base = _submit(client, [{"cidr": "10.0.0.0/24", "action": "permit"}])
    target = _submit(client, [{"cidr": "10.0.0.0/25", "action": "deny"}])

    data = _diff(client, base, target).json()
    assert data["base_id"] == base
    assert data["target_id"] == target

    by_type = {(c["change_type"]): c for c in data["changes"]}
    assert by_type["permit_to_deny"]["cidrs"] == ["10.0.0.0/25"]
    assert by_type["permit_to_deny"]["address_count"] == 128
    assert by_type["permit_to_none"]["cidrs"] == ["10.0.0.128/25"]
    assert by_type["permit_to_none"]["address_count"] == 128

    assert data["total_changed_addresses"] == 256
    assert data["total_change_range_count"] == 2
    assert data["by_change_type"]["permit_to_deny"] == {
        "change_range_count": 1,
        "changed_addresses": 128,
    }
    assert data["ipv4"]["changed_addresses"] == 256
    assert data["ipv6"]["changed_addresses"] == 0


def test_diff_is_directional(client: TestClient) -> None:
    base = _submit(client, [{"cidr": "10.0.0.0/24", "action": "permit"}])
    target = _submit(client, [{"cidr": "10.0.0.0/24", "action": "deny"}])

    forward = _diff(client, base, target).json()
    assert [c["change_type"] for c in forward["changes"]] == ["permit_to_deny"]
    reverse = _diff(client, target, base).json()
    assert [c["change_type"] for c in reverse["changes"]] == ["deny_to_permit"]


def test_diff_new_coverage_is_none_to_action(client: TestClient) -> None:
    base = _submit(client, [{"cidr": "10.0.0.0/25", "action": "deny"}])
    target = _submit(client, [{"cidr": "10.0.0.0/24", "action": "deny"}])
    data = _diff(client, base, target).json()
    # The first /25 denies in both versions (no change); the second half gains a rule.
    assert len(data["changes"]) == 1
    change = data["changes"][0]
    assert change["change_type"] == "none_to_deny"
    assert change["cidrs"] == ["10.0.0.128/25"]
    assert change["address_count"] == 128


def test_diff_merges_only_same_type_adjacent_ranges(client: TestClient) -> None:
    base = _submit(client, [{"cidr": "10.0.0.0/24", "action": "permit"}])
    # Two adjacent deny halves with an unchanged permit island between them:
    #   10.0.0.0/25      permit -> deny
    #   10.0.0.128/26    permit -> permit (must block merging)
    #   10.0.0.192/26    permit -> deny
    target = _submit(client, [
        {"cidr": "10.0.0.0/24", "action": "permit"},
        {"cidr": "10.0.0.0/25", "action": "deny"},
        {"cidr": "10.0.0.192/26", "action": "deny"},
    ])
    changes = _diff(client, base, target).json()["changes"]
    assert all(c["change_type"] == "permit_to_deny" for c in changes)
    # Same type, but not adjacent (an unchanged /26 lies between) -> two ranges.
    assert {tuple(c["cidrs"]) for c in changes} == {("10.0.0.0/25",), ("10.0.0.192/26",)}

    # Adjacent same-type halves DO coalesce into one minimal CIDR range.
    target2 = _submit(client, [
        {"cidr": "10.0.0.0/25", "action": "deny"},
        {"cidr": "10.0.0.128/25", "action": "deny"},
    ])
    changes2 = _diff(client, base, target2).json()["changes"]
    assert len(changes2) == 1
    assert changes2[0]["cidrs"] == ["10.0.0.0/24"]
    assert changes2[0]["address_count"] == 256


def test_diff_different_types_never_merge(client: TestClient) -> None:
    base = _submit(client, [{"cidr": "10.0.0.0/24", "action": "permit"}])
    # First half gains a deny rule (permit -> deny); the rule covering the
    # second half is removed (permit -> none).  The two change ranges are
    # adjacent but of different types and must stay separate.
    target = _submit(client, [{"cidr": "10.0.0.0/25", "action": "deny"}])
    changes = _diff(client, base, target).json()["changes"]
    types = sorted(c["change_type"] for c in changes)
    assert types == ["permit_to_deny", "permit_to_none"]
    assert all(c["cidrs"] != ["10.0.0.0/24"] for c in changes)


def test_diff_effective_fragments_of_nested_rules(client: TestClient) -> None:
    # Parent permit /24 with a deny child /25 in both versions; only the
    # parent's second half changes permit -> deny in the target.
    base = _submit(client, [
        {"cidr": "10.0.0.0/24", "action": "permit"},
        {"cidr": "10.0.0.0/25", "action": "deny"},
    ])
    target = _submit(client, [
        {"cidr": "10.0.0.0/24", "action": "deny"},
        {"cidr": "10.0.0.0/25", "action": "deny"},
    ])
    changes = _diff(client, base, target).json()["changes"]
    assert len(changes) == 1
    assert changes[0]["change_type"] == "permit_to_deny"
    # The parent's effective range in the base is exactly the second /25.
    assert changes[0]["cidrs"] == ["10.0.0.128/25"]


def test_diff_ipv6_counts_and_independence(client: TestClient) -> None:
    base = _submit(client, [{"cidr": "10.0.0.0/24", "action": "permit"}])
    target = _submit(client, [
        {"cidr": "10.0.0.0/24", "action": "permit"},
        {"cidr": "2001:db8::/32", "action": "deny"},
    ])
    data = _diff(client, base, target).json()
    assert data["ipv4"]["changed_addresses"] == 0
    assert data["ipv6"]["changed_addresses"] == 2 ** 96
    v6_changes = [c for c in data["changes"] if c["ip_version"] == 6]
    assert len(v6_changes) == 1
    assert v6_changes[0]["change_type"] == "none_to_deny"
    assert v6_changes[0]["cidrs"] == ["2001:db8::/32"]
    assert v6_changes[0]["address_count"] == 2 ** 96


def test_diff_disjoint_covered_universes(client: TestClient) -> None:
    base = _submit(client, [{"cidr": "10.0.0.0/24", "action": "permit"}])
    other = _submit(client, [{"cidr": "192.168.0.0/24", "action": "permit"}])
    data = _diff(client, base, other).json()
    # Disjoint universes: each side's block changes none <-> permit.
    assert data["total_changed_addresses"] == 512
    assert {c["change_type"] for c in data["changes"]} == {
        "none_to_permit",
        "permit_to_none",
    }


def test_diff_same_id_returns_400(client: TestClient) -> None:
    aid = _submit(client, [{"cidr": "10.0.0.0/24", "action": "permit"}])
    r = _diff(client, aid, aid)
    assert r.status_code == 400
    assert "different" in r.json()["detail"]


def test_diff_malformed_id_returns_400(client: TestClient) -> None:
    aid = _submit(client, [{"cidr": "10.0.0.0/24", "action": "permit"}])
    for bad in ("an_xyz", "AN_0123456789abcdef", "1234567890abcdef", "an_0123456789abcdef0", "nope"):
        r = _diff(client, aid, bad)
        assert r.status_code == 400, (bad, r.status_code, r.text)
        assert "invalid target" in r.json()["detail"]
        r = _diff(client, bad, aid)
        assert r.status_code == 400, (bad, r.status_code, r.text)
        assert "invalid base" in r.json()["detail"]


def test_diff_nonexistent_id_returns_404(client: TestClient) -> None:
    aid = _submit(client, [{"cidr": "10.0.0.0/24", "action": "permit"}])
    missing = "an_0000000000000000"
    assert missing != aid
    r = _diff(client, aid, missing)
    assert r.status_code == 404
    assert missing in r.json()["detail"]
    r = _diff(client, missing, aid)
    assert r.status_code == 404
    assert missing in r.json()["detail"]


def test_diff_missing_query_params_422_and_route_shadowing(client: TestClient) -> None:
    aid = _submit(client, [{"cidr": "10.0.0.0/24", "action": "permit"}])
    assert client.get("/api/analyses/diff", params={"base": aid}).status_code == 422
    # The literal 'diff' must still not be captured by the {analysis_id} route.
    assert client.get("/api/analyses/diff").status_code == 422
    assert client.get("/api/analyses/diff/rules").status_code == 404
