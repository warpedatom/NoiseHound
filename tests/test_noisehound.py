"""End-to-end and unit tests for NoiseHound.

Run: python -m pytest tests/  (or python tests/test_noisehound.py for a
dependency-light smoke run without pytest).
"""
import io
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import networkx as nx

from noisehound.annotate import annotate
from noisehound.corpus import load_corpus
from noisehound.environment import EnvironmentProfile
from noisehound.ingest import find_node, load_graph
from noisehound.schema import ScoringConfig, validate_entry, CorpusError
from noisehound.solver import score_path, solve

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(ROOT, "samples", "sample_graph.json")
AZURE = os.path.join(ROOT, "samples", "sample_azure.json")


def test_corpus_loads_and_validates():
    corpus = load_corpus()
    assert len(corpus) >= 15
    assert "DCSync" in corpus
    assert corpus.static_score("DCSync") == (85.0, True)
    # Case-insensitive lookup.
    assert corpus.static_score("dcsync")[0] == 85.0


def test_unknown_edge_fails_safe():
    corpus = load_corpus(default_unknown_noise=60)
    score, known = corpus.static_score("TotallyMadeUpEdge")
    assert score == 60.0
    assert known is False


def test_schema_rejects_bad_score():
    bad = {"edge_type": "X", "static_noise_score": 150, "telemetry": []}
    try:
        validate_entry(bad)
    except CorpusError:
        return
    raise AssertionError("expected CorpusError for out-of-range score")


def test_schema_rejects_bad_source():
    bad = {"edge_type": "X", "static_noise_score": 10,
           "telemetry": [{"source": "carrier_pigeon", "reliability": "low"}]}
    try:
        validate_entry(bad)
    except CorpusError:
        return
    raise AssertionError("expected CorpusError for invalid telemetry source")


def test_score_path_weighting():
    cfg = ScoringConfig()
    # max=25, mean=(2+25+20+2)/4=12.25 -> 25*0.6 + 12.25*0.4 = 19.9
    assert round(score_path([2, 25, 20, 2], cfg), 2) == 19.9
    assert score_path([], cfg) == 0.0


def test_config_weights_must_sum_to_one():
    try:
        ScoringConfig(max_weight=0.7, mean_weight=0.4).validate()
    except ValueError:
        return
    raise AssertionError("expected ValueError for weights not summing to 1")


def test_ingest_normalised_sample():
    g = load_graph(SAMPLE)
    assert g.number_of_nodes() == 9
    assert find_node(g, "jdoe") is not None
    # Friendly-name resolution without the @DOMAIN suffix.
    assert find_node(g, "Domain Admins") is not None


def test_solver_ranks_by_noise_not_hops():
    g = load_graph(SAMPLE)
    corpus = load_corpus()
    annotate(g, corpus)
    src = find_node(g, "jdoe")
    dst = find_node(g, "Domain Admins")
    paths = solve(g, src, dst, k=5)

    assert paths, "expected at least one path"
    # Quietest path should be the 4-hop session path, not the 2-hop
    # ForceChangePassword shortcut -> ranking is by noise, not hop count.
    top = paths[0]
    assert top.hop_count == 4
    assert round(top.path_score, 1) == 19.9
    # Scores must be non-decreasing across ranks.
    scores = [p.path_score for p in paths]
    assert scores == sorted(scores)
    # The 2-hop ForceChangePassword path must exist but rank lower (louder).
    fcp = [p for p in paths if any(e["edge_type"] == "ForceChangePassword" for e in p.edges)]
    assert fcp and fcp[0].path_score > top.path_score


def test_unknown_edge_marks_path():
    g = load_graph(SAMPLE)
    corpus = load_corpus()
    stats = annotate(g, corpus)
    assert "SyncedToEntraUser" in stats.unknown_types
    assert stats.unknown_edges >= 1
    assert stats.coverage < 1.0


def test_corpus_has_azure_edges():
    corpus = load_corpus()
    types = {e["edge_type"] for e in corpus}
    for az in ("AZGlobalAdmin", "AZAddSecret", "AZUserAccessAdministrator", "AZVMContributor"):
        assert az in types, "missing Azure edge %s" % az
    # Azure edges carry Entra-native telemetry that the schema accepts.
    add_secret = next(e for e in corpus if e["edge_type"] == "AZAddSecret")
    assert any(t["source"] == "entra_audit" for t in add_secret["telemetry"])
    # Real corpus scores (not the fail-safe default); passive rights score low.
    assert corpus.static_score("AZAddSecret") == (55.0, True)
    assert corpus.static_score("AZOwns")[0] < 45
    assert corpus.static_score("AZHasRole")[0] < 45


def test_azure_graph_scores_and_ranks():
    # The synthetic Entra graph is fully covered, and the quietest route to
    # Global Administrator hops through group ownership, not the VM or reset routes.
    g = load_graph(AZURE)
    stats = annotate(g, load_corpus())
    assert stats.coverage == 1.0
    paths = solve(g, find_node(g, "analyst@contoso.onmicrosoft.com"),
                  find_node(g, "Global Administrator"), k=5)
    assert paths
    # Quietest route hops through an owned, over-privileged service principal
    # (AZOwns -> AZHasRole), beating the louder secret/reset/VM routes.
    top_edges = [e["edge_type"] for e in paths[0].edges]
    assert "AZOwns" in top_edges and "AZHasRole" in top_edges
    assert round(paths[0].path_score, 1) == 39.6
    assert [p.path_score for p in paths] == sorted(p.path_score for p in paths)
    # AZAddSecret is corpus-scored (55), not the fail-safe default, and ranks louder.
    secret = [p for p in paths if any(e["edge_type"] == "AZAddSecret" for e in p.edges)]
    assert secret and secret[0].path_score > paths[0].path_score


def _annotated(edges, nodes=None):
    """Build and annotate a tiny normalised graph from an edge list."""
    node_ids = nodes or sorted({n for e in edges for n in (e[0], e[1])})
    doc = {
        "nodes": [{"id": n, "name": n} for n in node_ids],
        "edges": [{"source": s, "target": t, "edge_type": et} for s, t, et in edges],
    }
    tmp = os.path.join(ROOT, "samples", "_tmp_test_graph.json")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    try:
        g = load_graph(tmp)
    finally:
        os.remove(tmp)
    annotate(g, load_corpus())
    return g


def test_solver_prefers_uniformly_quiet_long_path():
    # A (loud, short): 2 x GenericAll(40) -> sum 80, score 0.6*40+0.4*40 = 40.
    # B (quiet, long): 4 x AdminTo(25)    -> sum 100, score 25 (quieter).
    # B has the *higher* weight-sum (100 > 80), so a min-sum / small-cap
    # k-shortest pass prefers A. Only the threshold-sweep backstop surfaces B.
    edges = [
        ("SRC", "A1", "GenericAll"), ("A1", "DST", "GenericAll"),                       # A
        ("SRC", "B1", "AdminTo"), ("B1", "B2", "AdminTo"),
        ("B2", "B3", "AdminTo"), ("B3", "DST", "AdminTo"),                              # B
    ]
    g = _annotated(edges)
    # candidate_paths=1 means the breadth pass contributes only the min-sum path
    # (A); B must come from the correctness backstop.
    cfg = ScoringConfig(candidate_paths=1)
    paths = solve(g, "SRC", "DST", k=5, config=cfg)
    assert paths[0].hop_count == 4
    assert round(paths[0].path_score, 1) == 25.0


def test_environment_profile_raises_auditing_sensitive_edges():
    corpus = load_corpus()
    # DCSync: 85 static; with 4662 object auditing declared it floors to 90.
    g = _annotated([("P", "DOM", "DCSync")])
    prof = EnvironmentProfile(object_auditing_4662=True)
    annotate(g, corpus, environment=prof)
    assert g["P"]["DOM"]["effective_noise_score"] == 90.0
    # Without the profile the static score stands.
    g2 = _annotated([("P", "DOM", "DCSync")])
    annotate(g2, corpus)
    assert g2["P"]["DOM"]["effective_noise_score"] == 85.0


def test_environment_hard_override_wins():
    g = _annotated([("A", "B", "HasSession")])
    prof = EnvironmentProfile(adjustments={"hassession": 72})
    annotate(g, load_corpus(), environment=prof)
    assert g["A"]["B"]["effective_noise_score"] == 72.0


def test_live_score_beats_environment():
    g = _annotated([("P", "DOM", "DCSync")])
    prof = EnvironmentProfile(object_auditing_4662=True)  # would push to 90
    annotate(g, load_corpus(), live_scores={("P", "DOM", "DCSync"): 12}, environment=prof)
    assert g["P"]["DOM"]["effective_noise_score"] == 12.0


def _bh_zip(files: dict) -> str:
    path = os.path.join(ROOT, "samples", "_tmp_bh.zip")
    with zipfile.ZipFile(path, "w") as zf:
        for name, doc in files.items():
            zf.writestr(name, json.dumps(doc))
    return path


def test_dcsync_synthesis_requires_both_replication_rights():
    # Domain object where P1 has both GetChanges+GetChangesAll (=> DCSync) and
    # P2 has only GetChanges (=> no DCSync edge).
    domain = {
        "meta": {"type": "domains"},
        "data": [{
            "ObjectIdentifier": "S-DOM",
            "Properties": {"name": "CORP.LOCAL"},
            "Aces": [
                {"PrincipalSID": "S-P1", "PrincipalType": "User", "RightName": "GetChanges"},
                {"PrincipalSID": "S-P1", "PrincipalType": "User", "RightName": "GetChangesAll"},
                {"PrincipalSID": "S-P2", "PrincipalType": "User", "RightName": "GetChanges"},
            ],
        }],
    }
    zpath = _bh_zip({"domains.json": domain})
    try:
        g = load_graph(zpath)
    finally:
        os.remove(zpath)
    assert g.has_edge("S-P1", "S-DOM")
    assert "DCSync" in g["S-P1"]["S-DOM"]["edge_types"]
    # P2 with only one replication right must NOT get a DCSync edge, and the raw
    # replication right must not become a standalone edge either.
    assert not g.has_edge("S-P2", "S-DOM")


def test_adcs_esc1_synthesis_and_pathing():
    dsid = "S-1-5-21-1"
    export = {
        "domains.json": {"meta": {"type": "domains"}, "data": [
            {"ObjectIdentifier": dsid,
             "Properties": {"name": "CORP.LOCAL", "domainsid": dsid}}]},
        "groups.json": {"meta": {"type": "groups"}, "data": [
            {"ObjectIdentifier": dsid + "-512",
             "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL"}, "Aces": []}]},
        "users.json": {"meta": {"type": "users"}, "data": [
            {"ObjectIdentifier": dsid + "-1105",
             "Properties": {"name": "JDOE@CORP.LOCAL"}, "Aces": []}]},
        "certtemplates.json": {"meta": {"type": "certtemplates"}, "data": [
            {"ObjectIdentifier": "T-ESC1",
             "Properties": {"name": "ESC1-TEMPLATE@CORP.LOCAL", "domainsid": dsid,
                            "enrolleesuppliessubject": True, "authenticationenabled": True,
                            "requiresmanagerapproval": False, "authorizedsignatures": 0,
                            "ekus": ["1.3.6.1.5.5.7.3.2"]},
             "Aces": [{"PrincipalSID": dsid + "-1105", "PrincipalType": "User",
                       "RightName": "Enroll"}]}]},
        "enterprisecas.json": {"meta": {"type": "enterprisecas"}, "data": [
            {"ObjectIdentifier": "CA-1",
             "Properties": {"name": "CORP-CA@CORP.LOCAL", "domainsid": dsid},
             "Aces": [],
             "EnabledCertTemplates": [{"ObjectIdentifier": "T-ESC1", "ObjectType": "CertTemplate"}]}]},
    }
    zpath = _bh_zip(export)
    try:
        g = load_graph(zpath)
    finally:
        os.remove(zpath)

    # ESC1 escalation edge: enrolling principal -> Domain Admins (RID 512).
    assert g.has_edge(dsid + "-1105", dsid + "-512")
    assert "ADCSESC1" in g[dsid + "-1105"][dsid + "-512"]["edge_types"]
    assert g.graph.get("adcs_edges_synthesized", 0) >= 1

    # And it is routable to the Domain Admins objective in one hop.
    annotate(g, load_corpus())
    src = find_node(g, "jdoe")
    dst = find_node(g, "Domain Admins")
    paths = solve(g, src, dst, k=3)
    assert paths and paths[0].edges[0]["edge_type"] == "ADCSESC1"


def test_adcs_manager_approval_blocks_esc1():
    # Same template but with manager approval required -> no ESC1 edge.
    dsid = "S-1-5-21-2"
    export = {
        "domains.json": {"meta": {"type": "domains"}, "data": [
            {"ObjectIdentifier": dsid, "Properties": {"name": "CORP2.LOCAL", "domainsid": dsid}}]},
        "certtemplates.json": {"meta": {"type": "certtemplates"}, "data": [
            {"ObjectIdentifier": "T2",
             "Properties": {"name": "T2@CORP2.LOCAL", "domainsid": dsid,
                            "enrolleesuppliessubject": True, "authenticationenabled": True,
                            "requiresmanagerapproval": True, "authorizedsignatures": 0,
                            "ekus": ["1.3.6.1.5.5.7.3.2"]},
             "Aces": [{"PrincipalSID": dsid + "-1200", "PrincipalType": "User", "RightName": "Enroll"}]}]},
        "enterprisecas.json": {"meta": {"type": "enterprisecas"}, "data": [
            {"ObjectIdentifier": "CA2", "Properties": {"name": "CA2@CORP2.LOCAL", "domainsid": dsid},
             "Aces": [], "EnabledCertTemplates": [{"ObjectIdentifier": "T2", "ObjectType": "CertTemplate"}]}]},
    }
    zpath = _bh_zip(export)
    try:
        g = load_graph(zpath)
    finally:
        os.remove(zpath)
    # No escalation edge because manager approval gates the abuse.
    assert not g.has_edge(dsid + "-1200", dsid)
    assert not g.has_edge(dsid + "-1200", dsid + "-512")


def test_adcs_esc9_10_13_synthesis():
    dsid = "S-1-5-21-9"
    da = dsid + "-512"
    grp13 = dsid + "-1400"           # the OID-linked privileged group (ESC13 target)
    oid13 = "1.3.6.1.4.1.311.21.8.777.13"
    export = {
        "domains.json": {"meta": {"type": "domains"}, "data": [
            {"ObjectIdentifier": dsid, "Properties": {"name": "CORP.LOCAL", "domainsid": dsid}}]},
        "groups.json": {"meta": {"type": "groups"}, "data": [
            {"ObjectIdentifier": da, "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL"}, "Aces": []},
            {"ObjectIdentifier": grp13, "Properties": {"name": "OID-LINKED-ADMINS@CORP.LOCAL"}, "Aces": []}]},
        "users.json": {"meta": {"type": "users"}, "data": [
            {"ObjectIdentifier": dsid + "-9001", "Properties": {"name": "U9@CORP.LOCAL"}, "Aces": []},
            {"ObjectIdentifier": dsid + "-9002", "Properties": {"name": "U10@CORP.LOCAL"}, "Aces": []},
            {"ObjectIdentifier": dsid + "-9003", "Properties": {"name": "U13@CORP.LOCAL"}, "Aces": []}]},
        "certtemplates.json": {"meta": {"type": "certtemplates"}, "data": [
            {"ObjectIdentifier": "T-ESC9",
             "Properties": {"name": "ESC9-T@CORP.LOCAL", "domainsid": dsid,
                            "authenticationenabled": True, "nosecurityextension": True,
                            "requiresmanagerapproval": False, "authorizedsignatures": 0,
                            "ekus": ["1.3.6.1.5.5.7.3.2"]},
             "Aces": [{"PrincipalSID": dsid + "-9001", "PrincipalType": "User", "RightName": "Enroll"}]},
            {"ObjectIdentifier": "T-ESC10",
             "Properties": {"name": "ESC10-T@CORP.LOCAL", "domainsid": dsid,
                            "authenticationenabled": True, "schannelauthenticationenabled": True,
                            "requiresmanagerapproval": False, "authorizedsignatures": 0,
                            "ekus": ["1.3.6.1.5.5.7.3.2"]},
             "Aces": [{"PrincipalSID": dsid + "-9002", "PrincipalType": "User", "RightName": "Enroll"}]},
            {"ObjectIdentifier": "T-ESC13",
             "Properties": {"name": "ESC13-T@CORP.LOCAL", "domainsid": dsid,
                            "authenticationenabled": True, "requiresmanagerapproval": False,
                            "authorizedsignatures": 0, "ekus": ["1.3.6.1.5.5.7.3.2"],
                            "issuancepolicies": [oid13]},
             "Aces": [{"PrincipalSID": dsid + "-9003", "PrincipalType": "User", "RightName": "Enroll"}]}]},
        "issuancepolicies.json": {"meta": {"type": "issuancepolicies"}, "data": [
            {"ObjectIdentifier": "IP-13",
             "Properties": {"name": "HIGHASSURANCE@CORP.LOCAL", "certtemplateoid": oid13},
             "GroupLink": {"ObjectIdentifier": grp13, "ObjectType": "Group"}}]},
        "enterprisecas.json": {"meta": {"type": "enterprisecas"}, "data": [
            {"ObjectIdentifier": "CA-9", "Properties": {"name": "CORP-CA@CORP.LOCAL", "domainsid": dsid},
             "Aces": [],
             "EnabledCertTemplates": [{"ObjectIdentifier": "T-ESC9", "ObjectType": "CertTemplate"},
                                      {"ObjectIdentifier": "T-ESC10", "ObjectType": "CertTemplate"},
                                      {"ObjectIdentifier": "T-ESC13", "ObjectType": "CertTemplate"}]}]},
    }
    zpath = _bh_zip(export)
    try:
        g = load_graph(zpath)
    finally:
        os.remove(zpath)

    # ESC9a (no-security-extension) and ESC10b (schannel) escalate to Domain Admins.
    assert "ADCSESC9a" in g[dsid + "-9001"][da]["edge_types"]
    assert "ADCSESC10b" in g[dsid + "-9002"][da]["edge_types"]
    # ESC13 escalates to the OID-LINKED GROUP, not Domain Admins.
    assert g.has_edge(dsid + "-9003", grp13)
    assert "ADCSESC13" in g[dsid + "-9003"][grp13]["edge_types"]
    assert not g.has_edge(dsid + "-9003", da)
    # ESC10a has no template-level signal and must never be synthesised.
    all_esc = {e for _, _, d in g.edges(data=True) for e in d.get("edge_types", [])}
    assert "ADCSESC10a" not in all_esc

    # The new ESC edges score and route like the others.
    annotate(g, load_corpus())
    assert g[dsid + "-9001"][da]["effective_noise_score"] > 0


def test_solver_scales_to_a_few_thousand_nodes():
    # Layered DAG, ~2000 nodes, each layer fully connected to the next by a low
    # branching factor. Confirms the solver returns promptly at scale.
    import time
    doc_nodes = []
    doc_edges = []
    layers = 200
    width = 10
    for L in range(layers):
        for w in range(width):
            doc_nodes.append({"id": "n_%d_%d" % (L, w), "name": "n_%d_%d" % (L, w)})
    for L in range(layers - 1):
        for w in range(width):
            for w2 in range(0, width, 5):  # branching factor 2
                doc_edges.append({"source": "n_%d_%d" % (L, w),
                                  "target": "n_%d_%d" % (L + 1, w2),
                                  "edge_type": "AdminTo"})
    tmp = os.path.join(ROOT, "samples", "_tmp_scale.json")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"nodes": doc_nodes, "edges": doc_edges}, fh)
    try:
        g = load_graph(tmp)
        annotate(g, load_corpus())
        # A small time budget makes the k-shortest pass self-bound, so this is
        # deterministic across machines (the threshold sweep still guarantees a
        # correct answer). The generous wall only catches a true runaway/hang.
        start = time.time()
        paths = solve(g, "n_0_0", "n_199_0", k=5,
                      config=ScoringConfig(candidate_paths=25, time_budget_s=3.0))
        elapsed = time.time() - start
    finally:
        os.remove(tmp)
    assert paths, "expected a path across the layered graph"
    assert elapsed < 30.0, "solver did not respect its time budget: %.1fs" % elapsed


def test_calibration_high_detection_raises_score():
    from noisehound.calibrate import calibrate_observation
    # 4/4 detections at high severity, well sampled -> score climbs toward ~85.
    rec = calibrate_observation(
        {"edge_type": "HasSession", "runs": 4, "detections": 4, "severity": "high"},
        static_score=20.0,
    )
    assert rec["detection_rate"] == 1.0
    # Climbs substantially from the static 20, but 4 runs of shrinkage keep it
    # short of the full 85 loudness - honest about sample size.
    assert rec["calibrated_score"] > 50
    assert rec["calibrated_score"] < 85
    assert rec["delta"] > 0


def test_calibration_no_detection_lowers_score():
    from noisehound.calibrate import calibrate_observation
    # 0/5 detections -> lab says quiet; score drops from the static estimate.
    rec = calibrate_observation(
        {"edge_type": "Kerberoast", "runs": 5, "detections": 0, "severity": "medium"},
        static_score=60.0,
    )
    assert rec["detection_rate"] == 0.0
    assert rec["calibrated_score"] < 60
    assert rec["delta"] < 0


def test_calibration_shrinks_toward_corpus_with_few_runs():
    from noisehound.calibrate import calibrate_observation
    # A single run should not swing the score far from the static estimate.
    one = calibrate_observation(
        {"edge_type": "X", "runs": 1, "detections": 1, "severity": "critical"},
        static_score=30.0,
    )
    many = calibrate_observation(
        {"edge_type": "X", "runs": 40, "detections": 40, "severity": "critical"},
        static_score=30.0,
    )
    assert many["calibrated_score"] > one["calibrated_score"]
    assert one["confidence_weight"] < many["confidence_weight"]


def test_calibration_confidence_interval_widens_with_fewer_runs():
    from noisehound.calibrate import calibrate_observation, calibrate, _wilson_ci
    one = calibrate_observation(
        {"edge_type": "X", "runs": 1, "detections": 1, "severity": "high"}, static_score=50.0)
    many = calibrate_observation(
        {"edge_type": "X", "runs": 40, "detections": 40, "severity": "high"}, static_score=50.0)
    span = lambda ci: ci[1] - ci[0]
    # A 1-run measurement must carry a wider score interval than a 40-run one.
    assert span(one["score_ci"]) > span(many["score_ci"])
    assert one["score_ci"][0] <= one["calibrated_score"] <= one["score_ci"][1]
    # Wilson interval: 1/1 is wide (not 0-width), 40/40 is tight and high.
    assert _wilson_ci(1, 1)[0] < 0.5 and _wilson_ci(40, 40)[0] > 0.9
    # calibrate() carries a per-edge confidence block (additive metadata).
    corpus = load_corpus()
    profile, _ = calibrate({"observations": [
        {"edge_type": "DCSync", "runs": 1, "detections": 1, "severity": "high"}]}, corpus)
    assert "confidence" in profile
    assert set(profile["confidence"]["DCSync"]) == {"runs", "detections", "rate_ci", "score_ci"}


def test_calibration_end_to_end_and_roundtrip():
    from noisehound.calibrate import calibrate
    from noisehound.environment import EnvironmentProfile
    detections = {
        "environment": "lab",
        "object_auditing_4662": True,
        "observations": [
            {"edge_type": "DCSync", "runs": 3, "detections": 3, "severity": "high"},
            {"edge_type": "AdminTo", "runs": 8, "detections": 1, "severity": "low"},
        ],
    }
    profile_dict, records = calibrate(detections, load_corpus())
    assert profile_dict["object_auditing_4662"] is True  # posture passed through
    assert set(profile_dict["adjustments"]) == {"DCSync", "AdminTo"}
    assert len(records) == 2

    # The emitted profile must drive annotate as a real environment profile.
    prof = EnvironmentProfile.from_dict(profile_dict)
    g = _annotated([("P", "DOM", "DCSync")])
    annotate(g, load_corpus(), environment=prof)
    assert g["P"]["DOM"]["effective_noise_score"] == profile_dict["adjustments"]["DCSync"]


def test_azure_edges_carry_entra_activity_signatures():
    # The measured Azure tier matches audit records by the activity signatures now
    # on the corpus. Abuse edges that write to the directory must carry them;
    # holding-only / resource-plane edges intentionally do not.
    from noisehound.entra import edge_signatures
    sigs = edge_signatures(load_corpus())
    assert "add member to role" in sigs["AZGlobalAdmin"]["activity"]  # stored lowercased
    assert "AZAddSecret" in sigs and "AZResetPassword" in sigs
    # AZHasRole holds a role (logs nothing) and AZVMContributor is resource-plane;
    # neither is directory-audit measurable, so no signature.
    assert "AZHasRole" not in sigs
    assert "AZVMContributor" not in sigs


def test_entra_counts_audit_hits_into_observations():
    from noisehound.entra import build_observations, edge_signatures, _records, _load
    sigs = edge_signatures(load_corpus())
    audit = _records(_load(os.path.join(ROOT, "samples", "entra_audit.example.json")))
    manifest = _load(os.path.join(ROOT, "samples", "entra_runs.example.json"))
    det = build_observations(manifest, audit, sigs)
    obs = {o["edge_type"]: o for o in det["observations"]}
    # GlobalAdmin: two matching role-add records in-window, but 1 run -> capped at runs.
    assert obs["AZGlobalAdmin"]["detections"] == 1
    # ResetPassword: 2 runs, only 1 matching audit record -> partial detection rate.
    assert obs["AZResetPassword"]["runs"] == 2
    assert obs["AZResetPassword"]["detections"] == 1
    # AZHasRole has no audit signature -> reported unmeasurable, not scored.
    assert "AZHasRole" in det["_unmeasurable"]
    assert "AZHasRole" not in obs


def test_entra_window_excludes_out_of_range_records():
    from noisehound.entra import build_observations, edge_signatures, _records, _load
    sigs = edge_signatures(load_corpus())
    audit = _records(_load(os.path.join(ROOT, "samples", "entra_audit.example.json")))
    # A window that ends before any record -> zero detections for a real edge.
    manifest = {"environment": "t", "observations": [
        {"edge_type": "AZAddMembers", "runs": 1,
         "start": "2020-01-01T00:00:00Z", "end": "2020-01-01T01:00:00Z"}]}
    det = build_observations(manifest, audit, sigs)
    assert det["observations"][0]["detections"] == 0


def test_entra_profile_calibrates_and_roundtrips():
    from noisehound.entra import build_observations, edge_signatures, _records, _load
    from noisehound.calibrate import calibrate
    from noisehound.environment import EnvironmentProfile
    sigs = edge_signatures(load_corpus())
    audit = _records(_load(os.path.join(ROOT, "samples", "entra_audit.example.json")))
    manifest = _load(os.path.join(ROOT, "samples", "entra_runs.example.json"))
    det = build_observations(manifest, audit, sigs)
    profile, records = calibrate(det, load_corpus())
    assert set(profile["adjustments"]) == {"AZGlobalAdmin", "AZAddMembers",
                                           "AZAddSecret", "AZResetPassword"}
    prof = EnvironmentProfile.from_dict(profile)
    g = _annotated([("P", "APP", "AZAddSecret")])
    annotate(g, load_corpus(), environment=prof)
    assert g["P"]["APP"]["effective_noise_score"] == profile["adjustments"]["AZAddSecret"]


def test_wdac_is_a_tool_signature_source_on_tool_edges():
    # WDAC / App Control is a tool-signature telemetry source: it fires on
    # off-the-shelf tool binaries and is blind to native/remote tradecraft. It
    # must be an accepted source, sit on the tool-abused edges, drive a defensive
    # recommendation, and NOT be miscredited to edges with no tool binary.
    from noisehound.schema import VALID_SOURCES
    from noisehound.defend import controls_for_edge
    assert "wdac" in VALID_SOURCES
    corpus = {e["edge_type"]: e for e in load_corpus()}
    for et in ("Kerberoast", "ASREPRoast", "DumpSMSAPassword", "DCSync",
               "AddKeyCredentialLink", "ADCSESC1"):
        tele = corpus[et]["telemetry"]
        wd = [t for t in tele if t.get("source") == "wdac"]
        assert wd, "%s should carry a wdac telemetry entry" % et
        assert wd[0].get("default_enabled") is False  # WDAC is opt-in, so it's a closable gap
        ctrls = controls_for_edge(corpus[et])
        assert any("WDAC" in c or "App Control" in c for c in ctrls), \
            "%s defensive controls should recommend WDAC" % et
    # A non-tool edge must not gain a WDAC recommendation.
    assert not any("WDAC" in c for c in controls_for_edge(corpus["AdminTo"]))


def test_corpus_validator_passes_clean():
    from noisehound.validate import validate_corpus
    errors, warnings, checked = validate_corpus(
        os.path.join(ROOT, "edge_mappings"))
    assert checked >= 40
    assert errors == []


def test_corpus_validator_catches_bad_files(tmp_path=None):
    from noisehound.validate import validate_corpus
    import tempfile
    d = tempfile.mkdtemp()
    try:
        # filename does not match edge_type + out-of-range score.
        with open(os.path.join(d, "Wrong.json"), "w", encoding="utf-8") as fh:
            json.dump({"edge_type": "Different", "static_noise_score": 999,
                       "telemetry": []}, fh)
        errors, warnings, checked = validate_corpus(d)
        assert checked == 1
        assert errors  # both the score range and the filename mismatch
    finally:
        import shutil
        shutil.rmtree(d)


def test_calibrate_template_covers_every_edge():
    from noisehound.calibrate import build_template
    corpus = load_corpus()
    tmpl = build_template(corpus)
    edges = {o["edge_type"] for o in tmpl["observations"]}
    assert "DCSync" in edges and "ADCSESC1" in edges
    assert len(edges) == len(corpus)


def test_calibration_plan_maps_edges_to_detect_events():
    from noisehound.calibrate import build_plan
    corpus = load_corpus()
    plan = build_plan(corpus)
    assert len(plan["edges"]) == len(corpus)
    by = {e["edge_type"]: e for e in plan["edges"]}
    # DCSync detection = Security 4662; the harness auto-scores on it.
    dcsync_ids = {(d["source"], d["event_id"]) for d in by["DCSync"]["detect_events"]}
    assert ("windows_security", 4662) in dcsync_ids
    # HasSession = Sysmon 10 (LSASS access).
    assert ("sysmon", 10) in {(d["source"], d["event_id"]) for d in by["HasSession"]["detect_events"]}
    # Every edge carries an abuse primitive and the edr flag for portal checks.
    assert all("abuse_primitive" in e and "edr_heuristic" in e for e in plan["edges"])


def test_plan_routes_system_log_events():
    # Regression: 7045 (SCM service-install) lives in the System log, not Security.
    # The plan must surface it as windows_system so the harness looks in the right log.
    from noisehound.calibrate import build_plan
    plan = build_plan(load_corpus())
    admin = {e["edge_type"]: e for e in plan["edges"]}["AdminTo"]
    sources = {(d["source"], d["event_id"]) for d in admin["detect_events"]}
    assert ("windows_system", 7045) in sources
    assert ("windows_security", 7045) not in sources


def test_schema_accepts_windows_system_source():
    ok = {"edge_type": "X", "static_noise_score": 10,
          "telemetry": [{"source": "windows_system", "event_id": 7045, "reliability": "high"}]}
    validate_entry(ok)  # must not raise


def test_calibrate_reads_bom_prefixed_input(tmp_path):
    # Regression: the PS 5.1 harness can emit UTF-8 with a BOM; the reader must tolerate it.
    from noisehound.calibrate import main as calibrate_main
    detections = {"environment": "bom-test",
                  "observations": [{"edge_type": "DCSync", "runs": 4, "detections": 4, "severity": "high"}]}
    src = tmp_path / "lab_detections.json"
    src.write_bytes(b"\xef\xbb\xbf" + json.dumps(detections).encode("utf-8"))
    out = tmp_path / "env.json"
    assert calibrate_main(["-i", str(src), "-o", str(out), "--quiet"]) == 0
    prof = json.loads(out.read_text(encoding="utf-8"))
    assert "DCSync" in prof["adjustments"]


def test_shipped_measured_profiles_are_valid():
    # The three lab-measured profiles must load and carry their calibrated adjustments.
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    expected = {
        "vulnad-hyperv-audit": ("DCSync", 59, 30),
        "vulnad-hyperv-edr": ("DCSync", 85, 30),
        "vulnad-hyperv-elastic": ("SQLAdmin", 64, 10),
    }
    for name, (edge, score, count) in expected.items():
        p = EnvironmentProfile.from_file(os.path.join(here, "profiles", name + ".json"))
        assert p.name == name
        assert len(p.adjustments) == count
        # adjustments are keyed lowercase internally
        assert p.adjustments[edge.lower()] == score
    # All four lateral edges are measured and present in the audit profile.
    audit = EnvironmentProfile.from_file(os.path.join(here, "profiles", "vulnad-hyperv-audit.json"))
    for lateral in ("canpsremote", "adminto", "executedcom", "sqladmin", "canrdp"):
        assert lateral in audit.adjustments


def _one_edge(edge_type, **annotate_kwargs):
    g = nx.DiGraph()
    g.add_node("A", name="A")
    g.add_node("B", name="B")
    g.add_edge("A", "B", edge_type=edge_type, edge_types=[edge_type])
    annotate(g, load_corpus(), **annotate_kwargs)
    return g["A"]["B"]


def test_tooling_axis_moves_signature_component():
    from noisehound.annotate import _tooling_base
    corpus = load_corpus()
    # DCSync default assumes on-host mimikatz (85); remote/native Impacket is quieter (59).
    assert _tooling_base(corpus.get("DCSync"), 85.0, None) == 85.0
    assert _tooling_base(corpus.get("DCSync"), 85.0, "remote") == 59.0
    assert _tooling_base(corpus.get("DCSync"), 85.0, "onhost") == 85.0
    # Kerberoast default is the tool-agnostic baseline (30); on-host Rubeus is louder (61).
    assert _tooling_base(corpus.get("Kerberoast"), 30.0, "onhost") == 61.0
    assert _tooling_base(corpus.get("Kerberoast"), 30.0, "remote") == 30.0


def test_tooling_does_not_lose_tool_agnostic_detection():
    # Remote DCSync still trips 4662/MDI when auditing is on - tooling moves only the
    # endpoint-signature component; the environment posture applies on top of the base.
    env = EnvironmentProfile.from_dict({"name": "x", "object_auditing_4662": True})
    quiet = _one_edge("DCSync", tooling="remote")
    audited = _one_edge("DCSync", tooling="remote", environment=env)
    assert quiet["effective_noise_score"] == 59.0
    assert audited["effective_noise_score"] == 90.0


def test_live_scores_override_by_edge_type():
    e = _one_edge("DCSync", live_scores={"DCSync": 12.0})
    assert e["effective_noise_score"] == 12.0
    assert e["live_noise_score"] == 12.0


def test_schema_tool_score_bounds():
    # agnostic must be <= static; signature must be >= static.
    for bad in ({"tool_agnostic_score": 60}, {"tool_signature_score": 20}):
        entry = {"edge_type": "X", "static_noise_score": 40, "telemetry": [], **bad}
        try:
            validate_entry(entry)
        except CorpusError:
            continue
        raise AssertionError("expected CorpusError for %s" % bad)
    validate_entry({"edge_type": "X", "static_noise_score": 40,
                    "tool_agnostic_score": 30, "tool_signature_score": 70, "telemetry": []})


def test_mdi_coverage_and_profile():
    from noisehound.mdi import compute_coverage, to_environment_profile
    corpus = load_corpus()
    cov = compute_coverage(corpus)
    # DCSync is a flagship MDI runtime alert (high floor); Kerberoast is medium.
    assert cov["DCSync"]["kind"] == "alert" and cov["DCSync"]["score"] == 85
    assert cov["Kerberoast"]["score"] == 70
    # Only real corpus edges are ever returned.
    assert set(cov) <= {e["edge_type"] for e in corpus}
    # Posture adds coverage (gMSA/LAPS) at a lower floor, labelled distinctly.
    cov_p = compute_coverage(corpus, include_posture=True)
    assert len(cov_p) > len(cov)
    assert cov_p["ReadLAPSPassword"]["kind"] == "posture"
    # The emitted profile loads as an environment profile and carries the floors.
    p = EnvironmentProfile.from_dict(to_environment_profile(cov))
    assert p.adjustments["dcsync"] == 85 and p.edr == "mdi"


def test_solver_respects_time_budget():
    # A tiny time budget must not prevent a correct answer (threshold sweep is
    # always run) and must return promptly.
    g = load_graph(SAMPLE)
    annotate(g, load_corpus())
    cfg = ScoringConfig(time_budget_s=0.001)
    paths = solve(g, find_node(g, "jdoe"), find_node(g, "Domain Admins"), config=cfg)
    assert paths and paths[0].hop_count == 4


def test_multidomain_objective_is_disambiguable():
    from noisehound.ingest import find_matches
    # Two forests, each with its own Domain Admins group.
    doc = {
        "nodes": [
            {"id": "S-A-512", "name": "Domain Admins@CONTOSO.LOCAL", "type": "Group"},
            {"id": "S-B-512", "name": "Domain Admins@FABRIKAM.LOCAL", "type": "Group"},
            {"id": "S-A-1", "name": "jdoe@CONTOSO.LOCAL", "type": "User"},
        ],
        "edges": [{"source": "S-A-1", "target": "S-A-512", "edge_type": "MemberOf"}],
    }
    tmp = os.path.join(ROOT, "samples", "_tmp_multidomain.json")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    try:
        g = load_graph(tmp)
    finally:
        os.remove(tmp)
    # Bare name is ambiguous across the two forests...
    assert len(find_matches(g, "Domain Admins")) == 2
    # ...but the @DOMAIN-qualified name resolves to exactly one.
    assert find_node(g, "Domain Admins@FABRIKAM.LOCAL") == "S-B-512"


def test_inspect_summary():
    from noisehound.inspect import summarise
    g = load_graph(SAMPLE)
    s = summarise(g, load_corpus())
    assert s["nodes"]["total"] == 9
    assert s["edges"]["total"] >= 10
    assert "SyncedToEntraUser" in s["corpus_coverage"]["unknown_types"]
    assert s["loudest_edge_types"][0]["effective_noise"] >= s["quietest_edge_types"][0]["effective_noise"]


def test_fullspectrum_sample_exercises_every_family():
    # The shipped full-spectrum fixture must parse every edge family the parser
    # and ADCS synthesis produce - guards all collection handlers at once, since
    # real exports may only contain a subset (e.g. ACL/ADCS-only collections).
    g = load_graph(os.path.join(ROOT, "samples", "sample_fullspectrum_ce.zip"))
    annotate(g, load_corpus())
    present = set()
    for _, _, d in g.edges(data=True):
        present.update(d.get("edge_types", []))
    expected = {
        "MemberOf", "GenericWrite", "AdminTo", "HasSession", "CanRDP",
        "CanPSRemote", "ExecuteDCOM", "AllowedToDelegate", "AllowedToAct",
        "DCSync", "CrossForestTrust", "Enroll", "ADCSESC1",
    }
    missing = expected - present
    assert not missing, "full-spectrum fixture missing families: %s" % sorted(missing)


def test_inspect_reports_adcs_synthesis():
    from noisehound.inspect import summarise
    g = load_graph(os.path.join(ROOT, "samples", "sample_adcs_ce.zip"))
    s = summarise(g, load_corpus())
    assert s["adcs_edges_synthesized"] >= 1
    assert "ADCSESC1" in s["edges"]["by_type"]


def test_bundled_lab_sample_is_bhce_ingestable():
    # sample_lab_ce.zip is a lightly-sanitised real SharpHound CE collection (the
    # public GOAD sevenkingdoms.local lab), shipped so the operator walkthrough is
    # a pure upload -> writeback -> view flow. It doubles as a BHCE-ingestion
    # regression fixture: it must parse with full corpus coverage and carry the
    # computer-access + session families that only a real collection produces -
    # AdminTo comes from the modern LocalGroups format, HasSession from Sessions.
    g = load_graph(os.path.join(ROOT, "samples", "sample_lab_ce.zip"))
    stats = annotate(g, load_corpus())
    assert stats.coverage == 1.0, "unknown edge types: %s" % sorted(stats.unknown_types)
    present = set()
    for _, _, d in g.edges(data=True):
        present.update(d.get("edge_types", []))
    assert {"AdminTo", "HasSession", "MemberOf", "DCSync"} <= present
    # The documented walkthrough path must stay solvable across refactors.
    src = find_node(g, "svc_deleg")
    dst = find_node(g, "Domain Admins")
    assert src is not None and dst is not None
    paths = solve(g, src, dst, k=1)
    assert paths, "svc_deleg -> Domain Admins path disappeared from the sample"


def test_defensive_detection_gap_analysis():
    from noisehound.defend import analyse
    g = load_graph(SAMPLE)
    corpus = load_corpus()
    annotate(g, corpus)
    paths = solve(g, find_node(g, "jdoe"), find_node(g, "Domain Admins"), k=3)
    report = analyse(g, corpus, paths)
    assert report["paths"]
    # The quietest path relies on quiet-by-default edges, so full instrumentation
    # must lift its score, and at least one closable gap must be found.
    top = report["paths"][0]
    assert top["instrumented_path_score"] >= top["current_path_score"]
    assert any(e["detection_gap"] > 0 for e in top["edges"])
    # HasSession (quiet token theft by default) should recommend a Sysmon control.
    assert report["recommended_controls"]
    assert any("Sysmon" in rc["control"] for rc in report["recommended_controls"])


def test_neo4j_live_path_with_mock_driver():
    # Exercises load_graph_from_neo4j end to end (query -> records -> graph) with
    # a fake driver, so the Bolt path is validated without a running server.
    import neo4j
    from noisehound.neo4j_ingest import load_graph_from_neo4j

    class FakeRecord(dict):
        pass

    class FakeSession:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def run(self, query, **params):
            if "labels(n)" in query:
                return [
                    FakeRecord(oid="S-1", labels=["Base", "User"],
                               name="jdoe@CONTOSO.LOCAL", props=None),
                    FakeRecord(oid="S-512", labels=["Base", "Group"],
                               name="Domain Admins@CONTOSO.LOCAL", props=None),
                ]
            return [FakeRecord(source="S-1", target="S-512", rtype="GenericAll")]

    class FakeDriver:
        def session(self, database=None): return FakeSession()
        def close(self): pass

    orig = neo4j.GraphDatabase.driver
    neo4j.GraphDatabase.driver = staticmethod(lambda uri, auth=None: FakeDriver())
    try:
        g = load_graph_from_neo4j("bolt://localhost:7687", "neo4j", "x")
    finally:
        neo4j.GraphDatabase.driver = orig
    assert g.number_of_nodes() == 2
    assert g.nodes["S-1"]["type"] == "User"
    assert g["S-1"]["S-512"]["edge_type"] == "GenericAll"


def test_bolt_path_reconstructs_and_synthesizes_esc():
    # The analysed DB stores ESC facts as relationships (template PublishedTo CA)
    # and node properties, not JSON fields. build_graph_from_records must fetch
    # props, rebuild the CA/template facts, and run synthesis - matching the zip
    # path - so live-Bolt ingestion is not blind to escalation edges.
    from noisehound.neo4j_ingest import build_graph_from_records
    dsid = "S-1-5-21-7"
    node_records = [
        {"oid": dsid, "labels": ["Base", "Domain"], "name": "CORP.LOCAL",
         "props": {"domainsid": dsid}},
        {"oid": dsid + "-512", "labels": ["Base", "Group"],
         "name": "DOMAIN ADMINS@CORP.LOCAL", "props": None},
        {"oid": dsid + "-1105", "labels": ["Base", "User"],
         "name": "JDOE@CORP.LOCAL", "props": None},
        {"oid": "T1", "labels": ["Base", "CertTemplate"], "name": "ESC10-T@CORP.LOCAL",
         "props": {"domainsid": dsid, "authenticationenabled": True,
                   "schannelauthenticationenabled": True, "requiresmanagerapproval": False,
                   "authorizedsignatures": 0, "ekus": ["1.3.6.1.5.5.7.3.2"]}},
        {"oid": "CA1", "labels": ["Base", "EnterpriseCA"],
         "name": "CORP-CA@CORP.LOCAL", "props": {"domainsid": dsid}},
    ]
    rel_records = [
        {"source": dsid + "-1105", "target": "T1", "rtype": "Enroll"},  # enroller
        {"source": "T1", "target": "CA1", "rtype": "PublishedTo"},      # published on the CA
    ]
    g = build_graph_from_records(node_records, rel_records)
    # enabled_templates rebuilt from PublishedTo; ESC10b synthesized to Domain Admins.
    assert g.nodes["CA1"]["enabled_templates"] == ["T1"]
    assert "ADCSESC10b" in g[dsid + "-1105"][dsid + "-512"]["edge_types"]
    assert g.graph["adcs_edges_synthesized"] >= 1


def test_writeback_builds_rows_and_runs_with_mock_driver():
    import neo4j
    from noisehound.writeback import write_scores
    g = _annotated([("S-1", "S-2", "GenericAll"), ("S-2", "S-512", "MemberOf")])
    captured = {}

    class FakeResult:
        def __init__(self, n): self.n = n
        def single(self): return {"c": self.n}

    class FakeSession:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def run(self, cypher, rows=None):
            captured["cypher"] = cypher
            captured["rows"] = rows
            return FakeResult(len(rows))

    class FakeDriver:
        def session(self, database=None): return FakeSession()
        def close(self): pass

    orig = neo4j.GraphDatabase.driver
    neo4j.GraphDatabase.driver = staticmethod(lambda uri, auth=None: FakeDriver())
    try:
        updated, attempted = write_scores(g, "bolt://localhost:7687", "neo4j", "x")
    finally:
        neo4j.GraphDatabase.driver = orig
    assert attempted == 2 and updated == 2
    assert "SET r.noise" in captured["cypher"]
    row = next(r for r in captured["rows"] if r["et"] == "GenericAll")
    assert row["s"] == "S-1" and row["t"] == "S-2" and row["n"] == 40.0


def test_writeback_dry_run_writes_nothing(capsys, monkeypatch):
    from noisehound import writeback
    # A dry run must never touch Neo4j: if it tries to construct a driver, fail loud.
    import neo4j
    monkeypatch.setattr(neo4j.GraphDatabase, "driver",
                        staticmethod(lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("dry run must not connect to Neo4j"))))
    rc = writeback.main(["-i", os.path.join(ROOT, "samples", "sample_lab_ce.zip"), "--dry-run"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "DRY RUN" in err and "nothing written" in err


def test_neo4j_record_to_graph():
    from noisehound.neo4j_ingest import build_graph_from_records, is_bolt_uri
    assert is_bolt_uri("bolt://localhost:7687")
    assert is_bolt_uri("neo4j+s://host:7687")
    assert not is_bolt_uri("export.zip")
    nodes = [
        {"oid": "S-1", "labels": ["Base", "User"], "name": "jdoe@CONTOSO.LOCAL"},
        {"oid": "S-512", "labels": ["Base", "Group"], "name": "Domain Admins@CONTOSO.LOCAL"},
        {"oid": "S-2", "labels": ["Base", "User"], "name": "svc@CONTOSO.LOCAL"},
    ]
    rels = [
        {"source": "S-1", "target": "S-2", "rtype": "GenericAll"},
        {"source": "S-2", "target": "S-512", "rtype": "MemberOf"},
    ]
    g = build_graph_from_records(nodes, rels)
    assert g.number_of_nodes() == 3
    assert g.nodes["S-1"]["type"] == "User"           # most specific label wins over Base
    assert g["S-1"]["S-2"]["edge_type"] == "GenericAll"
    # And it flows through annotate + solve like any other graph.
    annotate(g, load_corpus())
    paths = solve(g, "S-1", "S-512", k=1)
    assert paths and paths[0].hop_count == 2


def test_sigma_coverage_is_conservative():
    from noisehound.sigma import parse_rules, compute_coverage
    rules = parse_rules(os.path.join(ROOT, "samples", "sigma_rules"))
    assert len(rules) == 2
    cov = compute_coverage(load_corpus(), rules)
    # DCSync is covered by the replication rule (event 4662 + technique t1003.006).
    assert cov["DCSync"]["score"] == 85
    assert cov["DCSync"]["match"] == "event_id+technique"
    assert cov["AddMember"]["score"] == 70
    # Fail-safe: LAPS read and GenericAll also touch 4662 but the rule is scoped
    # to a different technique, so they must NOT be reported as covered.
    assert "ReadLAPSPassword" not in cov
    assert "GenericAll" not in cov
    # ForceChangePassword shares technique t1098 with the group rule but not its
    # event IDs, so a shared technique alone must not count as coverage.
    assert "ForceChangePassword" not in cov


def test_sigma_profile_roundtrips_into_scoring():
    from noisehound.sigma import parse_rules, compute_coverage, to_environment_profile
    from noisehound.environment import EnvironmentProfile
    rules = parse_rules(os.path.join(ROOT, "samples", "sigma_rules"))
    profile = to_environment_profile(compute_coverage(load_corpus(), rules))
    assert profile["adjustments"]["DCSync"] == 85
    # The emitted profile must drive annotate: a covered edge gets raised.
    prof = EnvironmentProfile.from_dict(profile)
    g = _annotated([("P", "DOM", "DCSync")])
    annotate(g, load_corpus(), environment=prof)
    assert g["P"]["DOM"]["effective_noise_score"] == 85


def test_elastic_query_event_id_parsing():
    from noisehound.elastic import _event_ids_from_query
    assert _event_ids_from_query("event.code:4662 and foo:bar") == {4662}
    assert _event_ids_from_query('winlog.event_id: "4624"') == {4624}
    # list form, both delimiters
    assert _event_ids_from_query("event.code:(4728 or 4729)") == {4728, 4729}
    assert _event_ids_from_query("process.name:mimikatz.exe") == set()


def test_elastic_normalise_skips_disabled_and_reads_attack():
    from noisehound.elastic import normalise_rules
    raw = json.load(open(os.path.join(ROOT, "samples", "elastic_rules.example.json"),
                        encoding="utf-8"))
    rules = normalise_rules(raw)
    # 5 rules in the fixture, one disabled (ESC1) -> 4 enabled.
    assert len(rules) == 4
    titles = {r.title for r in rules}
    assert not any("DISABLED" in t for t in titles)
    dcsync = next(r for r in rules if r.title.startswith("Active Directory Replication"))
    assert dcsync.event_ids == {4662}
    # Both the declared parent technique and its subtechnique are kept, matching
    # how the Sigma tier treats ATT&CK tags; _tech_match handles parent/sub.
    assert dcsync.techniques == {"T1003", "T1003.006"}


def test_elastic_technique_only_tier_is_opt_in():
    from noisehound.elastic import normalise_rules
    from noisehound.sigma import compute_coverage
    raw = json.load(open(os.path.join(ROOT, "samples", "elastic_rules.example.json"),
                        encoding="utf-8"))
    rules = normalise_rules(raw)
    # The AS-REP rule is an EQL query with no event.code, only technique T1558.004.
    off = compute_coverage(load_corpus(), rules)                          # Sigma default
    on = compute_coverage(load_corpus(), rules, allow_technique_only=True)  # SIEM tier
    assert "ASREPRoast" not in off, "technique-only match must not count by default"
    assert on["ASREPRoast"]["match"] == "technique"
    assert on["ASREPRoast"]["score"] == 65  # high floor 85 - 20 technique-only penalty
    # Event-grounded matches are identical either way.
    assert on["DCSync"]["match"] == off["DCSync"]["match"] == "event_id+technique"


def test_elastic_profile_roundtrips_into_scoring(capsys):
    from noisehound.elastic import main
    from noisehound.environment import EnvironmentProfile
    out = os.path.join(ROOT, "samples", "_tmp_elastic_env.json")
    try:
        rc = main(["--rules-json", os.path.join(ROOT, "samples", "elastic_rules.example.json"),
                   "--out", out, "--quiet"])
        assert rc == 0
        profile = json.load(open(out, encoding="utf-8"))
    finally:
        if os.path.exists(out):
            os.remove(out)
    assert profile["adjustments"]["DCSync"] == 85
    assert profile["adjustments"]["Kerberoast"] == 70
    assert profile["adjustments"]["ASREPRoast"] == 65
    prof = EnvironmentProfile.from_dict(profile)
    g = _annotated([("P", "DOM", "Kerberoast")])
    annotate(g, load_corpus(), environment=prof)
    assert g["P"]["DOM"]["effective_noise_score"] == 70


def test_elastic_structural_edges_excluded_from_denominator():
    from noisehound.elastic import _is_measurable, _render_report
    corpus = load_corpus()
    by = {e["edge_type"]: e for e in corpus}
    # Structural topology edges carry no technique and no telemetry event id.
    assert _is_measurable(by["Contains"]) is False
    assert _is_measurable(by["GpLink"]) is False
    # A real abuse is measurable: technique (AZVMContributor=T1651) or event id (DCSync).
    assert _is_measurable(by["AZVMContributor"]) is True
    assert _is_measurable(by["DCSync"]) is True
    # The report denominator counts measurable edges only, and names the excluded ones.
    n_measurable = sum(1 for e in corpus if _is_measurable(e))
    report = _render_report(corpus, {}, 0)
    assert "0/%d measurable edges" % n_measurable in report
    assert "Not measurable by this source" in report
    assert "Contains" in report.split("Not measurable")[1]
    assert "GpLink" in report.split("Not measurable")[1]


def test_path_detection_probability_model():
    from noisehound.probability import path_detection_probability, score_to_probability
    cfg = ScoringConfig(correlation=0.5)
    assert score_to_probability(30) == 0.3
    # Two quiet edges (p=0.2): noisy-OR=0.36, loudest=0.2 -> 0.5*0.2+0.5*0.36=0.28
    two = path_detection_probability([20, 20], cfg)
    assert round(two, 3) == 0.28
    # A longer all-quiet path has HIGHER detection probability (cumulative
    # exposure) even though every edge is individually quiet.
    four = path_detection_probability([20, 20, 20, 20], cfg)
    assert four > two
    assert path_detection_probability([], cfg) == 0.0


def test_solver_reports_and_can_rank_by_probability():
    g = load_graph(SAMPLE)
    annotate(g, load_corpus())
    src, dst = find_node(g, "jdoe"), find_node(g, "Domain Admins")
    by_noise = solve(g, src, dst, k=5)
    assert all(0.0 <= p.detection_probability <= 1.0 for p in by_noise)
    assert "detection_probability" in by_noise[0].to_dict()
    by_prob = solve(g, src, dst, k=5, rank_by="probability")
    probs = [p.detection_probability for p in by_prob]
    assert probs == sorted(probs)  # ascending when ranking by probability


def test_correlation_bounds_validated():
    try:
        ScoringConfig(correlation=1.5).validate()
    except ValueError:
        return
    raise AssertionError("expected ValueError for correlation out of range")


def test_pareto_frontier_keeps_tradeoffs():
    from noisehound.solver import solve_pareto
    g = load_graph(os.path.join(ROOT, "samples", "sample_fullspectrum_ce.zip"))
    annotate(g, load_corpus())
    src, dst = find_node(g, "ALICE"), find_node(g, "Domain Admins")
    front = solve_pareto(g, src, dst)
    assert front
    # The 4-hop quiet session path (low noise) and the 1-hop loud ADCS path
    # (fewest hops) are both non-dominated, so both are on the frontier.
    hop_counts = {p.hop_count for p in front}
    assert 4 in hop_counts and 1 in hop_counts
    # No frontier path dominates another on all three objectives.
    items = [(p.path_score, p.hop_count, p.detection_probability) for p in front]
    for a in items:
        for b in items:
            if a is b:
                continue
            assert not (b[0] <= a[0] and b[1] <= a[1] and b[2] <= a[2]
                        and (b[0] < a[0] or b[1] < a[1] or b[2] < a[2]))


def test_constraints_avoid_node_and_edge_type():
    from noisehound.constraints import apply_constraints
    from noisehound.solver import solve
    g = load_graph(os.path.join(ROOT, "samples", "sample_fullspectrum_ce.zip"))
    src, dst = find_node(g, "ALICE"), find_node(g, "Domain Admins")

    # Baseline quietest path routes through WS01 via a session.
    annotate(g, load_corpus())
    base = solve(g, src, dst, k=1)[0]
    assert any(e["edge_type"] == "HasSession" for e in base.edges)

    # Avoid the HasSession edge type -> the solver must find another route.
    ws01 = find_node(g, "WS01")
    h = apply_constraints(g, avoid_edge_types={"HasSession"}, keep_nodes={src, dst})
    annotate(h, load_corpus())
    alt = solve(h, src, dst, k=1)
    assert alt and not any(e["edge_type"] == "HasSession" for e in alt[0].edges)

    # Avoid WS01 entirely -> it must not appear on any returned path.
    h2 = apply_constraints(g, avoid_nodes={ws01}, keep_nodes={src, dst})
    assert ws01 not in h2
    annotate(h2, load_corpus())
    for p in solve(h2, src, dst, k=5):
        names = [e["from"] for e in p.edges] + [p.edges[-1]["to"]]
        assert "WS01@CONTOSO.LOCAL" not in names


def test_ingest_robust_to_malformed_input():
    # Malformed / partial BloodHound data must be tolerated, not crash: null
    # data arrays, nodes without ObjectIdentifier, ACEs missing fields, empty
    # results collections. Ingest should keep what it can.
    export = {
        "domains.json": {"meta": {"type": "domains"}, "data": None},  # null data
        "groups.json": {"meta": {"type": "groups"}, "data": [
            {"Properties": {"name": "NOID@X"}},                        # no ObjectIdentifier -> skipped
            {"ObjectIdentifier": "S-G1", "Properties": {"name": "G1@X"},
             "Members": [{"ObjectType": "User"}, {"ObjectIdentifier": "S-U1"}]},  # member missing id
            {"ObjectIdentifier": "S-G2", "Aces": [
                {"RightName": "GenericAll"},                            # ace missing PrincipalSID
                {"PrincipalSID": "S-U1", "RightName": "GenericAll"}]},
        ]},
        "computers.json": {"meta": {"type": "computers"}, "data": [
            {"ObjectIdentifier": "S-C1", "Properties": {"name": "C1@X"},
             "Sessions": {"Results": None}, "LocalAdmins": {}}]},        # null/empty collections
    }
    zpath = _bh_zip(export)
    try:
        g = load_graph(zpath)
    finally:
        os.remove(zpath)
    # Kept the well-formed relationships, dropped the malformed ones, no crash.
    assert g.has_edge("S-U1", "S-G1")   # valid member
    assert g.has_edge("S-U1", "S-G2")   # valid ACE
    assert "S-C1" in g


def test_empty_and_bad_inputs_raise_cleanly():
    import zipfile as _zf
    # Zip with no JSON -> clean ValueError, not a traceback.
    p = os.path.join(ROOT, "samples", "_tmp_empty.zip")
    with _zf.ZipFile(p, "w") as z:
        z.writestr("readme.txt", "not json")
    try:
        raised = False
        try:
            load_graph(p)
        except ValueError:
            raised = True
        assert raised
    finally:
        os.remove(p)


def test_kerberoast_asrep_synthesis():
    dsid = "S-1-5-21-9"
    export = {
        "domains.json": {"meta": {"type": "domains"}, "data": [
            {"ObjectIdentifier": dsid, "Properties": {"name": "CORP", "domainsid": dsid}}]},
        "groups.json": {"meta": {"type": "groups"}, "data": [
            {"ObjectIdentifier": dsid + "-513", "Properties": {"name": "DOMAIN USERS@CORP"},
             "Aces": [], "Members": []}]},
        "users.json": {"meta": {"type": "users"}, "data": [
            {"ObjectIdentifier": dsid + "-1", "Properties": {"name": "SVC_SQL@CORP", "hasspn": True}, "Aces": []},
            {"ObjectIdentifier": dsid + "-2", "Properties": {"name": "NOPREAUTH@CORP", "dontreqpreauth": True}, "Aces": []},
            {"ObjectIdentifier": dsid + "-502", "Properties": {"name": "KRBTGT@CORP", "hasspn": True}, "Aces": []},
        ]},
    }
    zpath = _bh_zip(export)
    try:
        g = load_graph(zpath)
    finally:
        os.remove(zpath)
    assert g.has_edge(dsid + "-513", dsid + "-1")
    assert g[dsid + "-513"][dsid + "-1"]["edge_type"] == "Kerberoast"
    assert g[dsid + "-513"][dsid + "-2"]["edge_type"] == "ASREPRoast"
    # krbtgt carries an SPN but must be excluded.
    assert not g.has_edge(dsid + "-513", dsid + "-502")


def test_ingest_reads_privileged_and_registry_sessions():
    # BloodHound CE splits sessions across Sessions / PrivilegedSessions /
    # RegistrySessions; LoggedOn (interactive) logons land in the latter two.
    # All must become HasSession edges (regression from a real loop export).
    export = {"computers.json": {"meta": {"type": "computers"}, "data": [{
        "ObjectIdentifier": "S-WS1",
        "Properties": {"name": "WS1@CORP"}, "Aces": [],
        "Sessions": {"Collected": True, "Results": []},
        "PrivilegedSessions": {"Collected": True, "Results": [
            {"UserSID": "S-U1", "ComputerSID": "S-WS1"}]},
        "RegistrySessions": {"Collected": True, "Results": [
            {"UserSID": "S-U2", "ComputerSID": "S-WS1"}]},
    }]}}
    zpath = _bh_zip(export)
    try:
        g = load_graph(zpath)
    finally:
        os.remove(zpath)
    assert g.has_edge("S-WS1", "S-U1")  # from PrivilegedSessions
    assert g.has_edge("S-WS1", "S-U2")  # from RegistrySessions
    assert g["S-WS1"]["S-U1"]["edge_type"] == "HasSession"


def test_ingest_reads_modern_localgroups():
    # SharpHound v2+/BloodHound CE report local-group membership under a single
    # LocalGroups list keyed by the group's SID; the trailing RID names the group
    # (544=Administrators, 555=RDP, 562=DCOM, 580=WinRM). The legacy per-collection
    # LocalAdmins/RemoteDesktopUsers/... arrays are gone from v2.13, so without a
    # LocalGroups handler NoiseHound silently drops AdminTo/CanRDP/ExecuteDCOM/
    # CanPSRemote on every current collection (regression from a real v2.13 export).
    comp = "S-1-5-21-1-2-3-1106"
    export = {"computers.json": {"meta": {"type": "computers"}, "data": [{
        "ObjectIdentifier": comp,
        "Properties": {"name": "WK1@CORP"}, "Aces": [],
        "LocalGroups": [
            {"ObjectIdentifier": comp + "-544",
             "Results": [{"ObjectIdentifier": "S-ADMIN", "ObjectType": "User"}]},
            {"ObjectIdentifier": comp + "-555",
             "Results": [{"ObjectIdentifier": "S-RDP", "ObjectType": "Group"}]},
            {"ObjectIdentifier": comp + "-562",
             "Results": [{"ObjectIdentifier": "S-DCOM", "ObjectType": "User"}]},
            {"ObjectIdentifier": comp + "-580",
             "Results": [{"ObjectIdentifier": "S-WINRM", "ObjectType": "User"}]},
            {"ObjectIdentifier": comp + "-513",  # unmapped RID must be ignored
             "Results": [{"ObjectIdentifier": "S-NOISE", "ObjectType": "User"}]},
        ],
    }]}}
    zpath = _bh_zip(export)
    try:
        g = load_graph(zpath)
    finally:
        os.remove(zpath)
    assert g["S-ADMIN"][comp]["edge_type"] == "AdminTo"
    assert g["S-RDP"][comp]["edge_type"] == "CanRDP"
    assert g["S-DCOM"][comp]["edge_type"] == "ExecuteDCOM"
    assert g["S-WINRM"][comp]["edge_type"] == "CanPSRemote"
    assert not g.has_edge("S-NOISE", comp)  # RID 513 has no edge mapping


def test_ingest_tolerates_utf8_bom_in_zip():
    # Real SharpHound / BloodHound CE exports sometimes write JSON with a UTF-8
    # BOM; ingest must strip it rather than choke (regression from a real export).
    doc = {"meta": {"type": "users"},
           "data": [{"ObjectIdentifier": "S-1", "Properties": {"name": "A@X"}, "Aces": []}]}
    raw = ("﻿" + json.dumps(doc)).encode("utf-8")  # explicit BOM prefix
    path = os.path.join(ROOT, "samples", "_tmp_bom.zip")
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("users.json", raw)
    try:
        g = load_graph(path)
    finally:
        os.remove(path)
    assert g.number_of_nodes() == 1


def test_emit_scored_graph():
    from noisehound.engine import emit_scored_graph
    g = load_graph(os.path.join(ROOT, "samples", "sample_fullspectrum_ce.zip"))
    annotate(g, load_corpus())
    sg = emit_scored_graph(g)
    assert len(sg["nodes"]) == g.number_of_nodes()
    assert len(sg["edges"]) == g.number_of_edges()
    e = sg["edges"][0]
    assert {"source", "target", "edge_type", "noise", "corpus_known"} <= set(e)
    assert isinstance(e["noise"], (int, float))


def test_deadair_engine_matches_python():
    # Only runs if the DeadAir binary is present; otherwise treated as a pass.
    from noisehound.engine import find_deadair, solve_with_deadair
    binary = find_deadair()
    if not binary:
        return  # DeadAir not built here; skip
    g = load_graph(os.path.join(ROOT, "samples", "sample_fullspectrum_ce.zip"))
    annotate(g, load_corpus())
    src, dst = find_node(g, "ALICE"), find_node(g, "Domain Admins")
    py = solve(g, src, dst, k=5)
    rs = solve_with_deadair(binary, g, src, dst, 5, ScoringConfig())
    assert len(rs) == len(py)
    for a, b in zip(py, rs):
        assert round(a.path_score, 1) == round(b.path_score, 1)
        assert a.hop_count == b.hop_count
        assert [e["edge_type"] for e in a.edges] == [e["edge_type"] for e in b.edges]


def test_azurehound_detection():
    from noisehound.azure_ingest import is_azurehound_doc
    assert is_azurehound_doc({"meta": {"type": "azure"}, "data": []})
    assert not is_azurehound_doc({"meta": {"type": "users"}, "data": []})
    assert not is_azurehound_doc({"nodes": [], "edges": []})


def _write_json(doc) -> str:
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".json", dir=os.path.join(ROOT, "samples"))
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    return path


def test_azure_ingest_real_sample_grounds_phase1_and_phase2():
    # The shipped sample is a trimmed-but-real azurehound v3.1 `list -o`
    # collection (DreadHost tenant recon, 2026-08-16) - not a synthetic
    # fixture. Regression-guards both the raw dispatch (AZHasRole from
    # AZRoleAssignment, AZOwns from the real ARM-nested AZSubscriptionOwner
    # record) and phase-2 synthesis (AZGlobalAdmin from templateId matching).
    g = load_graph(os.path.join(ROOT, "samples", "azurehound_native.example.json"))
    types = {d.get("type") for _, d in g.nodes(data=True)}
    assert {"AZTenant", "AZUser", "AZRole", "AZServicePrincipal", "AZApp", "AZSubscription"} <= types
    all_edges = {e for _, _, d in g.edges(data=True) for e in d.get("edge_types", [])}
    assert "AZHasRole" in all_edges
    assert "AZOwns" in all_edges
    assert "AZGlobalAdmin" in all_edges  # phase-2: synthesised, not in raw output
    assert g.graph["azure_edges_synthesized"] >= 1


def test_azure_synthesis_addmembers_addsecret_resetpassword():
    # Synthetic fixture exercising the resolution logic the real sample
    # doesn't reach: AZAddMembers (Groups Administrator -> groups), AZAddSecret
    # (App Administrator -> apps/SPs), and the AZResetPassword tiering (a
    # Password Administrator can reset a non-admin but not a Global Admin).
    from noisehound.azure_synthesis import (
        ROLE_GLOBAL_ADMIN, ROLE_GROUPS_ADMIN, ROLE_APP_ADMIN, ROLE_PASSWORD_ADMIN,
    )
    doc = {
        "meta": {"type": "azure", "count": 0},
        "data": [
            {"kind": "AZTenant", "data": {"id": "/TENANTS/T1", "displayName": "T"}},
            {"kind": "AZUser", "data": {"id": "U-GA", "displayName": "GA"}},
            {"kind": "AZUser", "data": {"id": "U-GROUPSADMIN", "displayName": "GROUPSADMIN"}},
            {"kind": "AZUser", "data": {"id": "U-APPADMIN", "displayName": "APPADMIN"}},
            {"kind": "AZUser", "data": {"id": "U-PWDADMIN", "displayName": "PWDADMIN"}},
            {"kind": "AZUser", "data": {"id": "U-PLAIN", "displayName": "PLAIN"}},
            {"kind": "AZGroup", "data": {"id": "GRP1", "displayName": "GRP1"}},
            {"kind": "AZApp", "data": {"id": "APP1", "displayName": "APP1"}},
            {"kind": "AZRole", "data": {"id": "R-GA", "templateId": ROLE_GLOBAL_ADMIN, "displayName": "Global Administrator"}},
            {"kind": "AZRole", "data": {"id": "R-GRP", "templateId": ROLE_GROUPS_ADMIN, "displayName": "Groups Administrator"}},
            {"kind": "AZRole", "data": {"id": "R-APP", "templateId": ROLE_APP_ADMIN, "displayName": "Application Administrator"}},
            {"kind": "AZRole", "data": {"id": "R-PWD", "templateId": ROLE_PASSWORD_ADMIN, "displayName": "Password Administrator"}},
            {"kind": "AZRoleAssignment", "data": {"roleAssignments": [{"principalId": "U-GA", "roleDefinitionId": "R-GA"}]}},
            {"kind": "AZRoleAssignment", "data": {"roleAssignments": [{"principalId": "U-GROUPSADMIN", "roleDefinitionId": "R-GRP"}]}},
            {"kind": "AZRoleAssignment", "data": {"roleAssignments": [{"principalId": "U-APPADMIN", "roleDefinitionId": "R-APP"}]}},
            {"kind": "AZRoleAssignment", "data": {"roleAssignments": [{"principalId": "U-PWDADMIN", "roleDefinitionId": "R-PWD"}]}},
        ],
    }
    path = _write_json(doc)
    try:
        g = load_graph(path)
    finally:
        os.remove(path)

    # AZAddMembers: Groups Administrator -> the group.
    assert "AZAddMembers" in g["U-GROUPSADMIN"]["GRP1"]["edge_types"]
    # AZAddSecret: Application Administrator -> the app.
    assert "AZAddSecret" in g["U-APPADMIN"]["APP1"]["edge_types"]
    # AZResetPassword tiering: Password Administrator can reset the plain user...
    assert "AZResetPassword" in g["U-PWDADMIN"]["U-PLAIN"]["edge_types"]
    # ...but not the Global Administrator (a lower-priv role can't reset a
    # higher-priv target - the whole point of postAzureResetPassword's tiers).
    assert not g.has_edge("U-PWDADMIN", "U-GA")


def test_azure_synthesis_addmembers_directory_writers_and_governance():
    # Regression for the review finding: post.go's non-role-assignable AddMembers
    # tier also includes Directory Writers + Identity Governance Administrator,
    # which were previously omitted (silent under-report). Confirm both now grant
    # AZAddMembers.
    from noisehound.azure_synthesis import (
        ROLE_DIRECTORY_WRITERS, ROLE_IDENTITY_GOVERNANCE_ADMIN,
    )
    doc = {
        "meta": {"type": "azure", "count": 0},
        "data": [
            {"kind": "AZTenant", "data": {"id": "/TENANTS/T1", "displayName": "T"}},
            {"kind": "AZUser", "data": {"id": "U-DW", "displayName": "DW"}},
            {"kind": "AZUser", "data": {"id": "U-IGA", "displayName": "IGA"}},
            {"kind": "AZGroup", "data": {"id": "GRP1", "displayName": "GRP1"}},
            {"kind": "AZRole", "data": {"id": "R-DW", "templateId": ROLE_DIRECTORY_WRITERS, "displayName": "Directory Writers"}},
            {"kind": "AZRole", "data": {"id": "R-IGA", "templateId": ROLE_IDENTITY_GOVERNANCE_ADMIN, "displayName": "Identity Governance Administrator"}},
            {"kind": "AZRoleAssignment", "data": {"roleAssignments": [{"principalId": "U-DW", "roleDefinitionId": "R-DW"}]}},
            {"kind": "AZRoleAssignment", "data": {"roleAssignments": [{"principalId": "U-IGA", "roleDefinitionId": "R-IGA"}]}},
        ],
    }
    path = _write_json(doc)
    try:
        g = load_graph(path)
    finally:
        os.remove(path)
    assert "AZAddMembers" in g["U-DW"]["GRP1"]["edge_types"]
    assert "AZAddMembers" in g["U-IGA"]["GRP1"]["edge_types"]


def test_azure_synthesis_directory_writers_excluded_from_resetpassword_nonadmin_tier():
    # Regression: adding a role to _ALL_NAMED_ROLES must actually exclude its
    # holders from the AZResetPassword "non-admin" target pool - a Password
    # Administrator can reset a plain user, but not someone who holds Directory
    # Writers (a named admin-ish role), even though that role grants no
    # AZResetPassword targeting of its own. Catches the DirectoryWriters/
    # IdentityGovernanceAdmin patch updating _ALL_NAMED_ROLES (unused elsewhere)
    # without updating the hand-listed non_admin_users exclusion that actually
    # gates this tier.
    from noisehound.azure_synthesis import ROLE_DIRECTORY_WRITERS, ROLE_PASSWORD_ADMIN
    doc = {
        "meta": {"type": "azure", "count": 0},
        "data": [
            {"kind": "AZUser", "data": {"id": "U-PWDADMIN", "displayName": "PWDADMIN"}},
            {"kind": "AZUser", "data": {"id": "U-DW", "displayName": "DW"}},
            {"kind": "AZUser", "data": {"id": "U-PLAIN", "displayName": "PLAIN"}},
            {"kind": "AZRole", "data": {"id": "R-PWD", "templateId": ROLE_PASSWORD_ADMIN, "displayName": "Password Administrator"}},
            {"kind": "AZRole", "data": {"id": "R-DW", "templateId": ROLE_DIRECTORY_WRITERS, "displayName": "Directory Writers"}},
            {"kind": "AZRoleAssignment", "data": {"roleAssignments": [{"principalId": "U-PWDADMIN", "roleDefinitionId": "R-PWD"}]}},
            {"kind": "AZRoleAssignment", "data": {"roleAssignments": [{"principalId": "U-DW", "roleDefinitionId": "R-DW"}]}},
        ],
    }
    path = _write_json(doc)
    try:
        g = load_graph(path)
    finally:
        os.remove(path)
    assert "AZResetPassword" in g["U-PWDADMIN"]["U-PLAIN"]["edge_types"]
    assert not g.has_edge("U-PWDADMIN", "U-DW")


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print("PASS %s" % fn.__name__)
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print("FAIL %s: %s" % (fn.__name__, exc))
    print("\n%d/%d passed" % (len(fns) - failed, len(fns)))
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
