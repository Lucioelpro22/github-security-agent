"""pnpm 8 uses v6 inline package graphs; no installation is performed."""

import pytest
import yaml

from github_security_agent import dependency_audit as audit


def lock(packages=None, **fields):
    return yaml.safe_dump(
        {"lockfileVersion": "6.0", "packages": {} if packages is None else packages, **fields},
        sort_keys=False,
    )


def report_for(tmp_path, text, **options):
    (tmp_path / "pnpm-lock.yaml").write_text(text, encoding="utf-8")
    return audit.audit_dependencies(tmp_path, **options)


def test_root_graph_inventories_direct_transitive_and_optional(tmp_path):
    report = report_for(
        tmp_path,
        lock(
            {
                "/app@1.0.0": {
                    "resolution": {"integrity": "sha512-opaque"},
                    "dependencies": {"child": "2.0.0"},
                    "optionalDependencies": {"optional": "3.0.0"},
                },
                "/child@2.0.0": {},
                "/optional@3.0.0": {"optional": True, "os": ["darwin"]},
            },
            dependencies={"app": {"specifier": "^1.0.0", "version": "1.0.0"}},
        ),
    )
    assert report.status == "complete"
    assert {(d.name, d.version, d.source_kind) for d in report.dependencies} == {
        ("app", "1.0.0", "unknown"),
        ("child", "2.0.0", "unknown"),
        ("optional", "3.0.0", "unknown"),
    }


@pytest.mark.parametrize("section", ["dependencies", "devDependencies", "optionalDependencies"])
def test_workspace_importers_and_scoped_aliases(tmp_path, section):
    report = report_for(
        tmp_path,
        lock(
            {"/@scope/actual@1.2.3": {}},
            importers={
                ".": {},
                "apps/example": {
                    section: {
                        "alias": {
                            "specifier": "npm:@scope/actual@^1.2.3",
                            "version": "/@scope/actual@1.2.3",
                        }
                    }
                },
            },
        ),
    )
    assert report.status == "complete"
    assert [(d.name, d.version) for d in report.dependencies] == [("@scope/actual", "1.2.3")]


@pytest.mark.parametrize("reference", ["/target@1.0.0", "target@1.0.0", "npm:target@1.0.0"])
def test_direct_and_transitive_alias_reference_forms(tmp_path, reference):
    report = report_for(
        tmp_path,
        lock(
            {"/parent@2.0.0": {"dependencies": {"alias": reference}}, "/target@1.0.0": {}},
            dependencies={"alias": {"specifier": "npm:target@^1", "version": reference}},
        ),
    )
    assert report.status == "complete"
    assert {d.name for d in report.dependencies} == {"parent", "target"}


@pytest.mark.parametrize("location", ["root", "importer", "transitive", "optional"])
def test_missing_reference_invalidates_inventory(tmp_path, location):
    packages = {"/parent@1.0.0": {}}
    fields = {}
    if location == "root":
        fields["dependencies"] = {"missing": {"specifier": "^2", "version": "2.0.0"}}
    elif location == "importer":
        fields["importers"] = {
            ".": {"dependencies": {"missing": {"specifier": "^2", "version": "2.0.0"}}}
        }
    else:
        section = "optionalDependencies" if location == "optional" else "dependencies"
        packages["/parent@1.0.0"][section] = {"missing": "2.0.0"}
    report = report_for(tmp_path, lock(packages, **fields))
    assert report.status == "incomplete"


@pytest.mark.parametrize("location", ["root", "transitive"])
def test_reference_requires_exact_peer_variant(tmp_path, location):
    packages = {"/child@1.0.0(peer@2.0.0)": {}, "/peer@2.0.0": {}}
    fields = {}
    if location == "root":
        fields["dependencies"] = {"child": {"specifier": "^1", "version": "1.0.0(peer@3.0.0)"}}
    else:
        packages["/parent@4.0.0"] = {"dependencies": {"child": "1.0.0(peer@3.0.0)"}}
    assert report_for(tmp_path, lock(packages, **fields)).status == "incomplete"


def test_all_peer_variants_are_validated_before_identity_deduplication(tmp_path):
    text = lock(
        {
            "/child@1.0.0(peer@2.0.0)": {},
            "/child@1.0.0(peer@3.0.0)": {"dependencies": {"missing": "9.0.0"}},
        }
    )
    assert report_for(tmp_path, text).status == "incomplete"


def test_exact_peer_variants_inventory_once(tmp_path):
    report = report_for(
        tmp_path,
        lock(
            {
                "/child@1.0.0(peer@2.0.0)": {},
                "/child@1.0.0(peer@3.0.0)": {},
            },
            dependencies={"child": {"specifier": "^1", "version": "1.0.0(peer@3.0.0)"}},
        ),
    )
    assert report.status == "complete"
    assert [(d.name, d.version) for d in report.dependencies] == [("child", "1.0.0")]


def test_nested_peer_context_in_v6_matches_exactly(tmp_path):
    variant = "1.0.0(peer@2.0.0(other@3.0.0))"
    report = report_for(
        tmp_path,
        lock(
            {f"/child@{variant}": {}},
            dependencies={"child": {"specifier": "^1", "version": variant}},
        ),
    )
    assert report.status == "complete"
    assert [(d.name, d.version) for d in report.dependencies] == [("child", "1.0.0")]


def test_v9_missing_specific_peer_variant_is_incomplete(tmp_path):
    text = yaml.safe_dump(
        {
            "lockfileVersion": "9.0",
            "importers": {
                ".": {
                    "dependencies": {"child": {"specifier": "^1", "version": "1.0.0(peer@3.0.0)"}}
                }
            },
            "packages": {"child@1.0.0": {}},
            "snapshots": {"child@1.0.0(peer@2.0.0)": {}},
        }
    )
    assert report_for(tmp_path, text).status == "incomplete"


def test_v9_all_variants_validate_before_deduplication(tmp_path):
    text = yaml.safe_dump(
        {
            "lockfileVersion": "9.0",
            "importers": {".": {}},
            "packages": {"child@1.0.0": {}},
            "snapshots": {
                "child@1.0.0(peer@2.0.0)": {},
                "child@1.0.0(peer@3.0.0)": {"dependencies": {"missing": "9.0.0"}},
            },
        },
        sort_keys=False,
    )
    assert report_for(tmp_path, text).status == "incomplete"


def test_two_documents_are_aggregated(tmp_path):
    text = lock({"/first@1.0.0": {}}) + "---\n" + lock({"/second@2.0.0": {}})
    report = report_for(tmp_path, text)
    assert report.status == "complete"
    assert {d.name for d in report.dependencies} == {"first", "second"}


@pytest.mark.parametrize(
    "text",
    [
        "lockfileVersion: '6.0'\npackages: {}\npackages: {}\n",
        "lockfileVersion: '6.0'\npackages: {'/foo@1.0.0': {}, '/foo@1.0.0': {}}\n",
        "lockfileVersion: '6.0'\npackages: &packages {}\n",
        "lockfileVersion: '6.0'\npackages: *packages\n",
        "!!python/object/apply:os.system ['touch SHOULD_NOT_EXIST']",
        lock() + "---\n" + lock() + "---\n" + lock(),
        lock() + "---\nnull\n",
        "lockfileVersion: '6.0'\npackages: []\n",
        "lockfileVersion: '6.0'\npackages: {'/foo@1.0.0': invalid}\n",
        lock({"/foo@1.0.0": {"dependencies": []}}),
        lock({"/foo@1.0.0": {"optionalDependencies": {"child": {"version": "1.0.0"}}}}),
        lock({"/foo@1.0.0(unclosed": {}}),
        lock({"/foo@not-an-exact-version": {}}),
        lock({"/foo@1.0.0": {}}, importers=[]),
        lock({"/foo@1.0.0": {}}, dependencies={"foo": {"specifier": "^1"}}),
    ],
)
def test_unsafe_or_malformed_lockfiles_are_incomplete(tmp_path, text):
    report = report_for(tmp_path, text)
    assert report.status == "incomplete"
    assert not (tmp_path / "SHOULD_NOT_EXIST").exists()


@pytest.mark.parametrize("version", ["5.4", "6.1", "8.0", "10.0"])
def test_other_lock_versions_remain_unsupported(tmp_path, version):
    text = lock().replace("'6.0'", f"'{version}'")
    report = report_for(tmp_path, text)
    assert report.status == "incomplete"
    assert report.dependencies == ()


@pytest.mark.parametrize("version", ["1foo", "1.2", "v1.2.3", "^1.2.3", "01.2.3", "1.2.3-01"])
def test_v6_package_version_requires_exact_semver(tmp_path, version):
    report = report_for(tmp_path, lock({f"/foo@{version}": {}}))
    assert report.status == "incomplete"
    assert report.dependencies == ()


@pytest.mark.parametrize("version", ["1.2.3-rc.1", "1.2.3+build.01", "1.2.3-alpha+build.2"])
def test_v6_exact_prerelease_and_build_versions_are_preserved(tmp_path, version):
    report = report_for(tmp_path, lock({f"/foo@{version}": {}}))
    assert report.status == "complete"
    assert report.dependencies[0].version == version


@pytest.mark.parametrize("suffix", ["()", "(peer@1.0.0", "(peer@1.0.0))", "(peer@1.0.0)trailing"])
def test_v6_malformed_peer_context_is_incomplete(tmp_path, suffix):
    report = report_for(tmp_path, lock({f"/foo@1.0.0{suffix}": {}}))
    assert report.status == "incomplete"
    assert report.dependencies == ()


def test_explicit_null_importers_does_not_fall_back_to_root(tmp_path):
    text = lock(
        {"/foo@1.0.0": {}},
        importers=None,
        dependencies={"foo": {"specifier": "^1", "version": "1.0.0"}},
    )
    report = report_for(tmp_path, text)
    assert report.status == "incomplete"
    assert report.dependencies == ()


@pytest.mark.parametrize("budget", ["MAX_PNPM_YAML_EVENTS", "MAX_PNPM_YAML_DEPTH"])
def test_yaml_resource_budget_is_enforced(tmp_path, monkeypatch, budget):
    monkeypatch.setattr(audit, budget, 2)
    report = report_for(tmp_path, lock({"/foo@1.0.0": {}}))
    assert report.status == "incomplete"
    assert report.dependencies == ()


def test_dependency_limit_marks_inventory_incomplete():
    records, incomplete = audit._parse_pnpm_lock(
        lock({"/first@1.0.0": {}, "/second@2.0.0": {}}), "pnpm-lock.yaml", 1
    )
    assert incomplete
    assert len(records) == 1


def test_osv_is_opt_in_and_unknown_origins_never_query(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("unexpected network"))
    text = lock({"/foo@1.0.0": {"resolution": {"integrity": "sha512-opaque"}}})
    assert report_for(tmp_path, text).status == "complete"
    queried = report_for(tmp_path, text, query_osv=True)
    assert queried.status == "incomplete"
    assert queried.advisory_lookup == "incomplete"
    assert queried.dependencies[0].source_kind == "unknown"


@pytest.mark.parametrize(
    "url",
    [
        "https://packages.internal/private-token/foo.tgz",
        "https://registry.npmjs.org.evil.example/foo.tgz",
        "http://registry.npmjs.org/foo.tgz",
        "https://user:private-token@registry.npmjs.org/foo.tgz",
        "https://registry.npmjs.org/foo.tgz?token=private-token",
    ],
)
def test_private_or_ambiguous_tarballs_are_not_sent_or_disclosed(tmp_path, monkeypatch, url):
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("unexpected network"))
    report = report_for(
        tmp_path,
        lock({"/foo@1.0.0": {"resolution": {"tarball": url}}}),
        query_osv=True,
    )
    assert report.status == "incomplete"
    assert report.dependencies[0].source_kind == "registry-other"
    assert url not in audit.report_json(report)
    assert "private-token" not in audit.report_markdown(report)


def test_only_exact_public_tarball_is_sent_when_requested(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(
        audit, "_post_osv_batch", lambda batch: sent.extend(batch) or [[] for _ in batch]
    )
    text = lock(
        {
            "/foo@1.0.0": {
                "resolution": {"tarball": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"}
            }
        }
    )
    assert report_for(tmp_path, text).status == "complete"
    assert sent == []
    report = report_for(tmp_path, text, query_osv=True)
    assert report.status == "complete"
    assert [(d.name, d.version) for d in sent] == [("foo", "1.0.0")]


@pytest.mark.parametrize("reference", ["link:../workspace", "workspace:*"])
def test_local_workspace_reference_is_not_followed(tmp_path, reference):
    report = report_for(
        tmp_path, lock(dependencies={"local": {"specifier": "workspace:*", "version": reference}})
    )
    assert report.status == "complete"
    assert report.dependencies == ()


@pytest.mark.parametrize(
    "reference", ["file:../private", "git+https://private.example/repo#secret"]
)
def test_unresolved_non_registry_refs_are_incomplete_without_disclosure(tmp_path, reference):
    report = report_for(
        tmp_path, lock(dependencies={"local": {"specifier": reference, "version": reference}})
    )
    assert report.status == "incomplete"
    assert reference not in audit.report_json(report)
