#!/usr/bin/env python3
"""Emit the reviewed ADR-0022 Phase-1 resource-provisioning command plan.

This tool is strictly non-mutating and has no apply mode. It prints a numbered
plan of exact `gcloud` commands (and deliberate omissions) for the Phase-1
archive GCS bucket, dedicated WIF pools/providers, registry-KMS version pin
verification, authoritative named Firestore witness database, and the
backup/export lane described by
`docs/adr/0022-phase1-resource-provisioning-plan.md`.  It never executes a
cloud command, never contacts the network, and refuses to run until every
operator-owned `REQUIRED_DECISION_*` value is supplied explicitly on the
command line, so the missing C-decisions stay machine-checkable.

Modes:
  (default)          print the numbered plan with per-step runbook justification
  --emit-shell PATH  additionally write a reviewable, fail-closed shell
                     transcript (`set -euo pipefail`; execution demands the
                     operator C4 approval digest in the environment)
  --plan-digest      print only `sha256:<hex>` of the canonicalized plan text,
                     the exact digest the C4 approval artifact signs

The plan proposes resource names for operator approval; it does not claim any
decision is made and it grants no permission.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import re
import shlex
import sys
from dataclasses import dataclass, fields
from pathlib import Path

PLAN_FORMAT = 1

# Pinned by the enclave source; a provisioning value that differs from these is
# wrong, not configurable (src/archive_v3_gcs_auth.rs,
# src/archive_v3_firestore_witness.rs).
ARCHIVE_GCS_POOL = "archive-gcs-attest"
ARCHIVE_GCS_PROVIDER = "archive-gcs"
ARCHIVE_WITNESS_POOL = "archive-witness-attest"
ARCHIVE_WITNESS_PROVIDER = "archive-witness"
WIF_AUDIENCE_PREFIX = "//iam.googleapis.com/projects/"
ARCHIVE_GCS_WIF_AUDIENCE_SUFFIX = (
    f"/locations/global/workloadIdentityPools/{ARCHIVE_GCS_POOL}"
    f"/providers/{ARCHIVE_GCS_PROVIDER}"
)
ARCHIVE_WITNESS_WIF_AUDIENCE_SUFFIX = (
    f"/locations/global/workloadIdentityPools/{ARCHIVE_WITNESS_POOL}"
    f"/providers/{ARCHIVE_WITNESS_PROVIDER}"
)
WITNESS_COLLECTION = "archive_witness_v3"

CONFIDENTIAL_SPACE_ISSUER = "https://confidentialcomputing.googleapis.com/"
ATTRIBUTE_MAPPING = (
    "google.subject=assertion.sub,"
    "attribute.image_digest=assertion.submods.container.image_digest"
)
ATTRIBUTE_CONDITION = (
    'assertion.swname == "CONFIDENTIAL_SPACE" && '
    '"STABLE" in assertion.submods.confidential_space.support_attributes'
)

ARCHIVE_OBJECT_WRITER_ROLE = "kiokuArchiveV3ObjectWriter"
ARCHIVE_OBJECT_WRITER_PERMISSIONS = "storage.objects.create,storage.objects.get"
WITNESS_WRITER_ROLE = "kiokuArchiveV3WitnessWriter"
WITNESS_WRITER_PERMISSIONS = (
    "datastore.databases.get,"
    "datastore.entities.create,datastore.entities.get,datastore.entities.update"
)
BACKUP_EXPORT_WRITER_ROLE = "kiokuArchiveV3BackupExportWriter"
BACKUP_EXPORT_WRITER_PERMISSIONS = (
    "storage.buckets.get,storage.objects.create,storage.objects.get"
)

LOCATION = "us-central1"
APPROVAL_ENV = "KIOKU_PHASE1_PLAN_APPROVAL_DIGEST"

DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
PROJECT_ID_PATTERN = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
DATABASE_ID_PATTERN = re.compile(r"[a-z][a-z0-9-]{2,61}[a-z0-9]\Z")
UUID_LIKE_PATTERN = re.compile(
    r"[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}\Z"
)
KMS_LOCATION_PATTERN = re.compile(r"[a-z0-9_-]{1,63}\Z")
KMS_RESOURCE_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,63}\Z")
U64_MAX = 18_446_744_073_709_551_615

RUNBOOK = "docs/adr/0022-production-activation-runbook.md"
PLAN_DOC = "docs/adr/0022-phase1-resource-provisioning-plan.md"


class DecisionError(SystemExit):
    """Raised with exit status 2 after the exact failures are printed."""


# Ordered operator decisions.  Every one is a mandatory CLI flag; the script
# has no defaults and refuses to substitute the proposals from the plan doc.
DECISION_FLAGS: tuple[tuple[str, str, str], ...] = (
    (
        "decision_archive_project",
        "REQUIRED_DECISION_ARCHIVE_PROJECT",
        "project ID owning the archive bucket, archive WIF pool, and existing KMS key"
        " (plan proposes kioku-joerodriguez)",
    ),
    (
        "decision_archive_project_number",
        "REQUIRED_DECISION_ARCHIVE_PROJECT_NUMBER",
        "numeric project number for the archive project (canonical u64)",
    ),
    (
        "decision_witness_project",
        "REQUIRED_DECISION_WITNESS_PROJECT",
        "project ID owning the witness database, witness WIF pool, and backups bucket"
        " (plan recommends kioku-joerodriguez initially; dedicated project is the"
        " documented alternative)",
    ),
    (
        "decision_witness_project_number",
        "REQUIRED_DECISION_WITNESS_PROJECT_NUMBER",
        "numeric project number for the witness project (canonical u64)",
    ),
    (
        "decision_witness_database",
        "REQUIRED_DECISION_WITNESS_DATABASE",
        "named Firestore witness database ID (plan proposes archive-v3-witness;"
        " (default) is refused)",
    ),
    (
        "decision_archive_bucket",
        "REQUIRED_DECISION_ARCHIVE_BUCKET",
        "archive object bucket name (plan proposes kioku-archive-v3-prod)",
    ),
    (
        "decision_backups_bucket",
        "REQUIRED_DECISION_BACKUPS_BUCKET",
        "separate witness-export backups bucket name"
        " (plan proposes kioku-archive-v3-backups)",
    ),
    (
        "decision_image_digest",
        "REQUIRED_DECISION_IMAGE_DIGEST",
        "approved release image digest (sha256:<64 hex>) that every principalSet"
        " member is pinned to",
    ),
    (
        "decision_kms_location",
        "REQUIRED_DECISION_KMS_LOCATION",
        "location of the existing production key ring (deploy history uses"
        " us-central1)",
    ),
    (
        "decision_kms_key_ring",
        "REQUIRED_DECISION_KMS_KEY_RING",
        "existing production key ring name holding kioku-kek",
    ),
    (
        "decision_kms_key",
        "REQUIRED_DECISION_KMS_KEY",
        "existing production KEK name (deploy history uses kioku-kek); no new key"
        " is created",
    ),
    (
        "decision_registry_kms_version",
        "REQUIRED_DECISION_REGISTRY_KMS_VERSION",
        "exact numeric enabled cryptoKeyVersion beneath the existing key that the"
        " registry adapter pins",
    ),
)


@dataclass(frozen=True)
class Decisions:
    archive_project: str
    archive_project_number: str
    witness_project: str
    witness_project_number: str
    witness_database: str
    archive_bucket: str
    backups_bucket: str
    image_digest: str
    kms_location: str
    kms_key_ring: str
    kms_key: str
    registry_kms_version: str


@dataclass(frozen=True)
class PlanStep:
    section: str
    title: str
    justification: str
    command: str
    mutating: bool
    expect: str = ""


def _canonical_u64(value: str) -> bool:
    return (
        1 <= len(value) <= 20
        and not value.startswith("0")
        and value.isascii()
        and value.isdecimal()
        and int(value) <= U64_MAX
    )


def _valid_bucket(value: str) -> bool:
    length_ok = (
        len(value) <= 222
        and all(component and len(component) <= 63 for component in value.split("."))
        if "." in value
        else len(value) <= 63
    )
    if not (
        length_ok
        and len(value) >= 3
        and value.isascii()
        and all(
            character.islower() or character.isdigit() or character in "-_."
            for character in value
        )
        and value[0].isalnum()
        and value[-1].isalnum()
        and not value.startswith("goog")
        and "google" not in value
        and "g00gle" not in value
    ):
        return False
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return True
    return False


def _valid_database_id(value: str) -> bool:
    return bool(DATABASE_ID_PATTERN.fullmatch(value)) and not UUID_LIKE_PATTERN.fullmatch(
        value
    )


def validate_decisions(values: dict[str, str | None]) -> Decisions:
    """Fail closed listing every missing/invalid REQUIRED_DECISION at once."""
    missing = [
        placeholder
        for flag, placeholder, _ in DECISION_FLAGS
        if not values.get(flag)
    ]
    problems: list[str] = []
    for flag, placeholder, _ in DECISION_FLAGS:
        value = values.get(flag)
        if value and "REQUIRED_DECISION" in value:
            problems.append(
                f"{placeholder}: the literal placeholder was supplied; this tool"
                " refuses to fill operator-owned decisions"
            )
    if missing or problems:
        for placeholder in missing:
            print(f"missing operator decision: {placeholder}", file=sys.stderr)
        for problem in problems:
            print(f"invalid operator decision: {problem}", file=sys.stderr)
        print(
            "refusing to emit a plan without every explicit operator decision;"
            f" see {PLAN_DOC}",
            file=sys.stderr,
        )
        raise DecisionError(2)

    checks: list[tuple[str, str, bool]] = [
        (
            "REQUIRED_DECISION_ARCHIVE_PROJECT",
            "must be a valid lowercase project ID",
            bool(PROJECT_ID_PATTERN.fullmatch(values["decision_archive_project"] or "")),
        ),
        (
            "REQUIRED_DECISION_ARCHIVE_PROJECT_NUMBER",
            "must be a canonical nonzero decimal u64 project number",
            _canonical_u64(values["decision_archive_project_number"] or ""),
        ),
        (
            "REQUIRED_DECISION_WITNESS_PROJECT",
            "must be a valid lowercase project ID",
            bool(PROJECT_ID_PATTERN.fullmatch(values["decision_witness_project"] or "")),
        ),
        (
            "REQUIRED_DECISION_WITNESS_PROJECT_NUMBER",
            "must be a canonical nonzero decimal u64 project number",
            _canonical_u64(values["decision_witness_project_number"] or ""),
        ),
        (
            "REQUIRED_DECISION_WITNESS_DATABASE",
            "must never be (default); the witness lives only in an explicitly"
            " named database",
            values["decision_witness_database"] != "(default)",
        ),
        (
            "REQUIRED_DECISION_WITNESS_DATABASE",
            "must match the named-database grammar shared with the runtime profile",
            _valid_database_id(values["decision_witness_database"] or ""),
        ),
        (
            "REQUIRED_DECISION_ARCHIVE_BUCKET",
            "must be a valid bucket name",
            _valid_bucket(values["decision_archive_bucket"] or ""),
        ),
        (
            "REQUIRED_DECISION_BACKUPS_BUCKET",
            "must be a valid bucket name",
            _valid_bucket(values["decision_backups_bucket"] or ""),
        ),
        (
            "REQUIRED_DECISION_BACKUPS_BUCKET",
            "must differ from the archive bucket",
            values["decision_backups_bucket"] != values["decision_archive_bucket"],
        ),
        (
            "REQUIRED_DECISION_IMAGE_DIGEST",
            "must be sha256:<64 lowercase hex> of the approved release image",
            bool(DIGEST_PATTERN.fullmatch(values["decision_image_digest"] or "")),
        ),
        (
            "REQUIRED_DECISION_KMS_LOCATION",
            "must be a lowercase KMS location ID",
            bool(KMS_LOCATION_PATTERN.fullmatch(values["decision_kms_location"] or "")),
        ),
        (
            "REQUIRED_DECISION_KMS_KEY_RING",
            "must be a KMS resource ID",
            bool(KMS_RESOURCE_PATTERN.fullmatch(values["decision_kms_key_ring"] or "")),
        ),
        (
            "REQUIRED_DECISION_KMS_KEY",
            "must be a KMS resource ID",
            bool(KMS_RESOURCE_PATTERN.fullmatch(values["decision_kms_key"] or "")),
        ),
        (
            "REQUIRED_DECISION_REGISTRY_KMS_VERSION",
            "must be the canonical nonzero decimal version number beneath the"
            " existing key",
            _canonical_u64(values["decision_registry_kms_version"] or ""),
        ),
    ]
    failures = [
        f"{placeholder}: {reason}" for placeholder, reason, ok in checks if not ok
    ]
    if failures:
        for failure in failures:
            print(f"invalid operator decision: {failure}", file=sys.stderr)
        raise DecisionError(2)

    return Decisions(
        archive_project=values["decision_archive_project"] or "",
        archive_project_number=values["decision_archive_project_number"] or "",
        witness_project=values["decision_witness_project"] or "",
        witness_project_number=values["decision_witness_project_number"] or "",
        witness_database=values["decision_witness_database"] or "",
        archive_bucket=values["decision_archive_bucket"] or "",
        backups_bucket=values["decision_backups_bucket"] or "",
        image_digest=values["decision_image_digest"] or "",
        kms_location=values["decision_kms_location"] or "",
        kms_key_ring=values["decision_kms_key_ring"] or "",
        kms_key=values["decision_kms_key"] or "",
        registry_kms_version=values["decision_registry_kms_version"] or "",
    )


def archive_gcs_audience(project_number: str) -> str:
    return f"{WIF_AUDIENCE_PREFIX}{project_number}{ARCHIVE_GCS_WIF_AUDIENCE_SUFFIX}"


def archive_witness_audience(project_number: str) -> str:
    return f"{WIF_AUDIENCE_PREFIX}{project_number}{ARCHIVE_WITNESS_WIF_AUDIENCE_SUFFIX}"


def _principal_set(project_number: str, pool: str, image_digest: str) -> str:
    return (
        f"principalSet://iam.googleapis.com/projects/{project_number}"
        f"/locations/global/workloadIdentityPools/{pool}"
        f"/attribute.image_digest/{image_digest}"
    )


def _join(argv: list[str]) -> str:
    return shlex.join(argv)


def build_plan(d: Decisions) -> list[PlanStep]:
    gcs_audience = archive_gcs_audience(d.archive_project_number)
    witness_audience = archive_witness_audience(d.witness_project_number)
    gcs_principal = _principal_set(
        d.archive_project_number, ARCHIVE_GCS_POOL, d.image_digest
    )
    witness_principal = _principal_set(
        d.witness_project_number, ARCHIVE_WITNESS_POOL, d.image_digest
    )
    database_resource = f"projects/{d.witness_project}/databases/{d.witness_database}"
    firestore_service_agent = (
        f"serviceAccount:service-{d.witness_project_number}"
        "@gcp-sa-firestore.iam.gserviceaccount.com"
    )
    condition = (
        f'expression=resource.name == "{database_resource}"'
        f' || resource.name.startsWith("{database_resource}/"),'
        "title=archive-v3-witness-exact-database,"
        "description=Only the one named witness database and its documents"
    )

    steps: list[PlanStep] = []

    def step(
        section: str,
        title: str,
        justification: str,
        argv: list[str],
        mutating: bool,
        expect: str = "",
    ) -> None:
        steps.append(
            PlanStep(
                section=section,
                title=title,
                justification=justification,
                command=_join(argv),
                mutating=mutating,
                expect=expect,
            )
        )

    preflight = "A. Preflight verification (read-only)"
    step(
        preflight,
        "Record the executing operator identity",
        f"{RUNBOOK} 'Cloud authority' row: explicit permission must name the"
        " operator; the C4 approval artifact records this account.",
        ["gcloud", "config", "get-value", "account"],
        mutating=False,
        expect="the exact operator account named in the C4 approval artifact",
    )
    step(
        preflight,
        "Confirm the archive project number decision",
        f"{RUNBOOK} 'Runtime coordinates' row requires the exact numeric project;"
        " src/archive_v3_gcs_auth.rs derives the STS audience only from this"
        " number.",
        [
            "gcloud",
            "projects",
            "describe",
            d.archive_project,
            "--format=value(projectNumber)",
        ],
        mutating=False,
        expect=d.archive_project_number,
    )
    step(
        preflight,
        "Confirm the witness project number decision",
        f"{RUNBOOK} 'Runtime coordinates' row requires the named witness"
        " project/number; src/archive_v3_firestore_witness.rs derives the witness"
        " STS audience only from this number.",
        [
            "gcloud",
            "projects",
            "describe",
            d.witness_project,
            "--format=value(projectNumber)",
        ],
        mutating=False,
        expect=d.witness_project_number,
    )
    step(
        preflight,
        "Verify the pinned registry KMS version beneath the existing key",
        "src/archive_v3_registry_kms.rs accepts one numeric version beneath the"
        " already-selected legacy production key and revalidates it as ENABLED"
        " GOOGLE_SYMMETRIC_ENCRYPTION at SOFTWARE protection on every operation;"
        " no new key, ring, or version is created by this plan.",
        [
            "gcloud",
            "kms",
            "keys",
            "versions",
            "describe",
            d.registry_kms_version,
            "--project",
            d.archive_project,
            "--location",
            d.kms_location,
            "--keyring",
            d.kms_key_ring,
            "--key",
            d.kms_key,
            "--format=value(state,algorithm,protectionLevel)",
        ],
        mutating=False,
        expect="ENABLED GOOGLE_SYMMETRIC_ENCRYPTION SOFTWARE",
    )
    step(
        preflight,
        "Audit the existing KEK policy without changing it",
        f"{RUNBOOK} execution step 3: confirm no standing human decrypt and no"
        " broad enumeration/delete role. This plan adds no KMS IAM; the"
        " per-digest binding continues to flow only through the reviewed deploy"
        " path. Confirm the bound role also covers cloudkms.cryptoKeyVersions.get,"
        " which the registry adapter's per-operation revalidation requires; any"
        " gap is a separately reviewed deploy-flow amendment, not a new standing"
        " grant here.",
        [
            "gcloud",
            "kms",
            "keys",
            "get-iam-policy",
            d.kms_key,
            "--project",
            d.archive_project,
            "--location",
            d.kms_location,
            "--keyring",
            d.kms_key_ring,
        ],
        mutating=False,
        expect="only image_digest-gated principalSet members hold decrypt",
    )

    wif = "B. Dedicated workload-identity pools and providers"
    step(
        wif,
        f"Create the {ARCHIVE_GCS_POOL} pool",
        "src/archive_v3_gcs_auth.rs pins pool/provider"
        f" {ARCHIVE_GCS_POOL}/{ARCHIVE_GCS_PROVIDER}; a dedicated pool keeps the"
        " archive object identity separate from the existing KEK pool.",
        [
            "gcloud",
            "iam",
            "workload-identity-pools",
            "create",
            ARCHIVE_GCS_POOL,
            "--project",
            d.archive_project,
            "--location",
            "global",
            "--display-name",
            "ADR-0022 archive GCS attestation",
        ],
        mutating=True,
    )
    step(
        wif,
        f"Create the {ARCHIVE_GCS_PROVIDER} provider with the exact pinned audience",
        "The enclave requests a no-nonce Confidential Space token for exactly"
        f" this audience string (src/archive_v3_gcs_auth.rs): {gcs_audience} ."
        " The attribute condition mirrors the existing kioku-kek binding"
        " (README.md 'Confidential Space and KMS').",
        [
            "gcloud",
            "iam",
            "workload-identity-pools",
            "providers",
            "create-oidc",
            ARCHIVE_GCS_PROVIDER,
            "--project",
            d.archive_project,
            "--location",
            "global",
            "--workload-identity-pool",
            ARCHIVE_GCS_POOL,
            "--display-name",
            "ADR-0022 archive GCS provider",
            "--issuer-uri",
            CONFIDENTIAL_SPACE_ISSUER,
            "--allowed-audiences",
            gcs_audience,
            "--attribute-mapping",
            ATTRIBUTE_MAPPING,
            "--attribute-condition",
            ATTRIBUTE_CONDITION,
        ],
        mutating=True,
    )
    step(
        wif,
        f"Create the {ARCHIVE_WITNESS_POOL} pool",
        "src/archive_v3_firestore_witness.rs accepts only the dedicated witness"
        f" WIF audience under pool/provider"
        f" {ARCHIVE_WITNESS_POOL}/{ARCHIVE_WITNESS_PROVIDER}.",
        [
            "gcloud",
            "iam",
            "workload-identity-pools",
            "create",
            ARCHIVE_WITNESS_POOL,
            "--project",
            d.witness_project,
            "--location",
            "global",
            "--display-name",
            "ADR-0022 archive witness attestation",
        ],
        mutating=True,
    )
    step(
        wif,
        f"Create the {ARCHIVE_WITNESS_PROVIDER} provider with the exact pinned audience",
        "The witness bearer path (src/archive_v3_firestore_auth.rs) exchanges a"
        f" no-nonce launcher token for exactly this audience: {witness_audience} .",
        [
            "gcloud",
            "iam",
            "workload-identity-pools",
            "providers",
            "create-oidc",
            ARCHIVE_WITNESS_PROVIDER,
            "--project",
            d.witness_project,
            "--location",
            "global",
            "--workload-identity-pool",
            ARCHIVE_WITNESS_POOL,
            "--display-name",
            "ADR-0022 archive witness provider",
            "--issuer-uri",
            CONFIDENTIAL_SPACE_ISSUER,
            "--allowed-audiences",
            witness_audience,
            "--attribute-mapping",
            ATTRIBUTE_MAPPING,
            "--attribute-condition",
            ATTRIBUTE_CONDITION,
        ],
        mutating=True,
    )
    step(
        wif,
        "Verify the archive GCS provider resource name matches the code pin",
        "The enclave refuses any other audience; the provider name must equal the"
        " code-derived audience minus the //iam.googleapis.com/ prefix.",
        [
            "gcloud",
            "iam",
            "workload-identity-pools",
            "providers",
            "describe",
            ARCHIVE_GCS_PROVIDER,
            "--project",
            d.archive_project,
            "--location",
            "global",
            "--workload-identity-pool",
            ARCHIVE_GCS_POOL,
            "--format=value(name)",
        ],
        mutating=False,
        expect=gcs_audience.removeprefix("//iam.googleapis.com/"),
    )
    step(
        wif,
        "Verify the witness provider resource name matches the code pin",
        "Same byte-for-byte audience requirement for the witness path.",
        [
            "gcloud",
            "iam",
            "workload-identity-pools",
            "providers",
            "describe",
            ARCHIVE_WITNESS_PROVIDER,
            "--project",
            d.witness_project,
            "--location",
            "global",
            "--workload-identity-pool",
            ARCHIVE_WITNESS_POOL,
            "--format=value(name)",
        ],
        mutating=False,
        expect=witness_audience.removeprefix("//iam.googleapis.com/"),
    )

    bucket = "C. Archive object bucket"
    step(
        bucket,
        "Create the archive bucket",
        f"{RUNBOOK} 'Runtime coordinates' row (archive bucket). Uniform"
        " bucket-level access and enforced public-access prevention are hard"
        " requirements; the region matches the production VM zone family.",
        [
            "gcloud",
            "storage",
            "buckets",
            "create",
            f"gs://{d.archive_bucket}",
            "--project",
            d.archive_project,
            "--location",
            LOCATION,
            "--uniform-bucket-level-access",
            "--public-access-prevention",
        ],
        mutating=True,
    )
    step(
        bucket,
        "Enable object versioning on the archive bucket",
        "Immutable-object accidental-overwrite forensics: the runtime creates"
        " exact names with ifGenerationMatch=0 preconditions"
        " (src/archive_v3_gcs.rs); versioning preserves evidence if any"
        " precondition is ever bypassed by a defect.",
        [
            "gcloud",
            "storage",
            "buckets",
            "update",
            f"gs://{d.archive_bucket}",
            "--versioning",
        ],
        mutating=True,
    )
    step(
        bucket,
        "Verify the archive bucket posture",
        "Public-access prevention must read enforced, uniform bucket-level access"
        " and versioning on, and the default soft-delete policy retained"
        " unchanged. No lifecycle rule and no retention lock may exist (see"
        " deliberate omissions).",
        [
            "gcloud",
            "storage",
            "buckets",
            "describe",
            f"gs://{d.archive_bucket}",
            "--format=yaml(public_access_prevention,uniform_bucket_level_access,"
            "versioning_enabled,soft_delete_policy)",
        ],
        mutating=False,
        expect=(
            "public_access_prevention: enforced; uniform_bucket_level_access:"
            " true; versioning_enabled: true; default soft_delete_policy"
        ),
    )
    step(
        bucket,
        "Create the custom archive object-writer role",
        "Least privilege for the WAL publisher, which retains only exact-name"
        " immutable create/get authority (0022-activation-readiness.md); the"
        " permanent no-go list forbids enumerate/delete through the WAL runtime,"
        " so this role deliberately grants neither list nor delete nor update.",
        [
            "gcloud",
            "iam",
            "roles",
            "create",
            ARCHIVE_OBJECT_WRITER_ROLE,
            "--project",
            d.archive_project,
            "--title",
            "Kioku archive-v3 object writer",
            "--description",
            "Exact-name immutable object create and get only.",
            "--permissions",
            ARCHIVE_OBJECT_WRITER_PERMISSIONS,
            "--stage",
            "GA",
        ],
        mutating=True,
    )
    step(
        bucket,
        "Bind the digest-pinned enclave identity to the archive bucket",
        "Mirrors the existing kioku-kek binding pattern: the only member is a"
        " principalSet bound to the exact approved image digest attribute, so"
        " only the attested release image can write archive objects.",
        [
            "gcloud",
            "storage",
            "buckets",
            "add-iam-policy-binding",
            f"gs://{d.archive_bucket}",
            "--member",
            gcs_principal,
            "--role",
            f"projects/{d.archive_project}/roles/{ARCHIVE_OBJECT_WRITER_ROLE}",
        ],
        mutating=True,
    )

    witness = "D. Authoritative named witness database"
    step(
        witness,
        "Create the named witness database",
        f"{RUNBOOK} 'Runtime coordinates' row requires a named witness database;"
        " src/archive_v3_firestore_witness.rs addresses only an explicitly named"
        " database and never (default). Delete protection is reversible and"
        " guards the settlement ledger against accidental removal.",
        [
            "gcloud",
            "firestore",
            "databases",
            "create",
            "--project",
            d.witness_project,
            "--database",
            d.witness_database,
            "--location",
            LOCATION,
            "--type",
            "firestore-native",
            "--delete-protection",
        ],
        mutating=True,
    )
    step(
        witness,
        "Enable point-in-time recovery on the witness database",
        "Backup/restore basis for the acknowledgement-critical witness ledger;"
        " PITR is content-free here because witness records are opaque"
        " commitment bytes.",
        [
            "gcloud",
            "firestore",
            "databases",
            "update",
            "--project",
            d.witness_project,
            "--database",
            d.witness_database,
            "--enable-pitr",
        ],
        mutating=True,
    )
    step(
        witness,
        "Create the custom witness-writer role",
        "The adapter needs only read-write transactions over exact witness"
        " documents: datastore.databases.get for transaction begin/rollback plus"
        " entity create/get/update for the strict"
        f" {WITNESS_COLLECTION}/{{archive_id_lowerhex}} records; no delete, no"
        " query enumeration, no index authority.",
        [
            "gcloud",
            "iam",
            "roles",
            "create",
            WITNESS_WRITER_ROLE,
            "--project",
            d.witness_project,
            "--title",
            "Kioku archive-v3 witness writer",
            "--description",
            "Named-database witness record create, get, and update only.",
            "--permissions",
            WITNESS_WRITER_PERMISSIONS,
            "--stage",
            "GA",
        ],
        mutating=True,
    )
    step(
        witness,
        "Bind the digest-pinned enclave identity to the one named database",
        "Conditional binding scoped to the exact database resource name (and its"
        " documents) so the grant cannot reach (default) or any other database"
        " in the project; the member is the image_digest-pinned principalSet"
        " from the dedicated witness pool.",
        [
            "gcloud",
            "projects",
            "add-iam-policy-binding",
            d.witness_project,
            "--member",
            witness_principal,
            "--role",
            f"projects/{d.witness_project}/roles/{WITNESS_WRITER_ROLE}",
            "--condition",
            condition,
        ],
        mutating=True,
    )
    step(
        witness,
        "Verify the witness database posture",
        "The database must be the named one (never (default)) with PITR and"
        " delete protection enabled.",
        [
            "gcloud",
            "firestore",
            "databases",
            "describe",
            "--project",
            d.witness_project,
            "--database",
            d.witness_database,
            "--format=yaml(name,pointInTimeRecoveryEnablement,deleteProtectionState)",
        ],
        mutating=False,
        expect=(
            f"name: {database_resource};"
            " pointInTimeRecoveryEnablement: POINT_IN_TIME_RECOVERY_ENABLED;"
            " deleteProtectionState: DELETE_PROTECTION_ENABLED"
        ),
    )

    backups = "E. Witness backup export lane"
    step(
        backups,
        "Create the separate backups bucket",
        "Scheduled witness exports land in their own bucket so backup authority"
        " never touches the archive bucket; same enforced public-access"
        " prevention and uniform access posture.",
        [
            "gcloud",
            "storage",
            "buckets",
            "create",
            f"gs://{d.backups_bucket}",
            "--project",
            d.witness_project,
            "--location",
            LOCATION,
            "--uniform-bucket-level-access",
            "--public-access-prevention",
        ],
        mutating=True,
    )
    step(
        backups,
        "Verify the backups bucket posture",
        "Public-access prevention must read enforced before any export runs.",
        [
            "gcloud",
            "storage",
            "buckets",
            "describe",
            f"gs://{d.backups_bucket}",
            "--format=yaml(public_access_prevention,uniform_bucket_level_access)",
        ],
        mutating=False,
        expect=(
            "public_access_prevention: enforced; uniform_bucket_level_access: true"
        ),
    )
    step(
        backups,
        "Create the custom backup export-writer role",
        "Export-only lane for the Google-managed Firestore service agent:"
        " bucket get plus object create/get, nothing else. If a supervised"
        " export drill proves the managed exporter needs one more permission,"
        " that exact permission arrives by reviewed amendment, never by a broad"
        " role.",
        [
            "gcloud",
            "iam",
            "roles",
            "create",
            BACKUP_EXPORT_WRITER_ROLE,
            "--project",
            d.witness_project,
            "--title",
            "Kioku archive-v3 witness backup export writer",
            "--description",
            "Firestore managed-export writes into the dedicated backups bucket only.",
            "--permissions",
            BACKUP_EXPORT_WRITER_PERMISSIONS,
            "--stage",
            "GA",
        ],
        mutating=True,
    )
    step(
        backups,
        "Bind the Firestore service agent to the backups bucket only",
        "The only non-principalSet member in this plan: the Google-managed"
        " Firestore export service agent, scoped to the backups bucket with the"
        " export-only custom role. Backup infrastructure never gains plaintext:"
        " witness records are opaque commitments and archive objects are"
        " enclave-encrypted ciphertext.",
        [
            "gcloud",
            "storage",
            "buckets",
            "add-iam-policy-binding",
            f"gs://{d.backups_bucket}",
            "--member",
            firestore_service_agent,
            "--role",
            f"projects/{d.witness_project}/roles/{BACKUP_EXPORT_WRITER_ROLE}",
        ],
        mutating=True,
    )
    step(
        backups,
        "Run the first supervised witness export drill",
        "First export proves the export-only grant suffices and seeds the"
        " restore drill required by the activation tracker's B4 drill harness"
        f" ({RUNBOOK} 'Phase-1 drills' row). Recurrence cadence is operator"
        " policy recorded with the C4 approval; no standing scheduler identity"
        " is created by this plan.",
        [
            "gcloud",
            "firestore",
            "export",
            f"gs://{d.backups_bucket}/{d.witness_database}/export-drill-0001",
            "--project",
            d.witness_project,
            "--database",
            d.witness_database,
        ],
        mutating=True,
    )

    return steps


DELIBERATE_OMISSIONS: tuple[str, ...] = (
    "No KMS key, key ring, version, or KMS IAM change: the registry adapter pins"
    " an existing enabled version beneath the already-selected production key,"
    " and per-digest KMS access continues to flow only through the reviewed"
    " deploy binding flow.",
    "No lifecycle deletion rule on any bucket: deletion authority is Phase-6"
    " work and must arrive with its own reviewed plan and identity.",
    "No retention lock on the archive bucket: a locked retention policy would"
    " irreversibly block the reviewed Phase-6 deletion path; revisit the"
    " decision at Phase 6 with its own review.",
    "No object list, object delete, object update, or IAM-set permission in any"
    " granted role, and no predefined role anywhere in this plan.",
    "No standing human or service-account decrypt or plaintext read: everything"
    " at rest is enclave-encrypted ciphertext or content-free witness"
    " commitments, and backup infrastructure holds export-write authority only.",
    "No scheduler, cron, or automation identity for recurring exports: the"
    " recurrence cadence is operator policy recorded at C4 approval.",
    "No versioning toggle on the backups bucket: exports write fresh timestamped"
    " prefixes; revisit only with a reviewed backup-lifecycle change.",
    "No manual witness document write, ever: adoption happens only through the"
    " sealed genesis creator (src/archive_v3_genesis.rs), which admits every"
    " create through the encrypted-control ledger before commit.",
    "No runtime-profile activation, image publication, deployment roll,"
    " monitoring deployment, or canary execution: those remain separate"
    f" decisions and evidence rows in {RUNBOOK}.",
)


def canonical_plan_text(d: Decisions) -> str:
    lines: list[str] = []
    lines.append(
        "ADR-0022 Phase-1 resource provisioning plan"
        " (proposed; grants no permission)"
    )
    lines.append(f"plan-format: {PLAN_FORMAT}")
    lines.append(f"plan-doc: {PLAN_DOC}")
    lines.append("operator decisions:")
    for (flag, placeholder, _), field in zip(DECISION_FLAGS, fields(Decisions)):
        del flag
        lines.append(f"  {placeholder} = {getattr(d, field.name)}")
    lines.append("")
    section = ""
    for number, item in enumerate(build_plan(d), start=1):
        if item.section != section:
            section = item.section
            lines.append(f"section {section}")
        kind = "mutating" if item.mutating else "read-only"
        lines.append(f"step {number} ({kind}): {item.title}")
        lines.append(f"  justification: {item.justification}")
        lines.append(f"  command: {item.command}")
        if item.expect:
            lines.append(f"  expect: {item.expect}")
    lines.append("")
    lines.append("deliberate omissions (no command is emitted for these):")
    for omission in DELIBERATE_OMISSIONS:
        lines.append(f"  - {omission}")
    lines.append("")
    lines.append(
        "This plan proposes; it does not approve. Executing any mutating step"
        " requires the operator C4 approval artifact binding this plan's digest."
    )
    return "\n".join(lines) + "\n"


def plan_digest(d: Decisions) -> str:
    return "sha256:" + hashlib.sha256(canonical_plan_text(d).encode("utf-8")).hexdigest()


def render_shell(d: Decisions) -> str:
    digest = plan_digest(d)
    lines: list[str] = [
        "#!/usr/bin/env bash",
        "# ADR-0022 Phase-1 resource provisioning - reviewed command transcript.",
        "# Generated by scripts/phase1_provision_archive_resources.py --emit-shell;",
        "# the generator is non-mutating and never executes these commands.",
        f"# Plan digest: {digest}",
        f"# Plan document: {PLAN_DOC}",
        "#",
        "# Executing this file mutates cloud resources. It refuses to run unless",
        "# the operator C4 approval digest is supplied in the environment.",
        "set -euo pipefail",
        "",
        f'if [[ "${{{APPROVAL_ENV}:-}}" != "{digest}" ]]; then',
        f'  echo "refusing: {APPROVAL_ENV} must hold the operator-approved plan'
        ' digest (C4)" >&2',
        "  exit 1",
        "fi",
    ]
    section = ""
    for number, item in enumerate(build_plan(d), start=1):
        lines.append("")
        if item.section != section:
            section = item.section
            lines.append(f"## section {section}")
        kind = "mutating" if item.mutating else "read-only"
        lines.append(f"# step {number} ({kind}): {item.title}")
        lines.append(f"# justification: {item.justification}")
        if item.expect:
            lines.append(f"# expect: {item.expect}")
        lines.append(item.command)
    lines.append("")
    lines.append("# Deliberate omissions (nothing below is performed):")
    for omission in DELIBERATE_OMISSIONS:
        lines.append(f"# - {omission}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phase1_provision_archive_resources.py",
        description=(
            "Print the reviewed ADR-0022 Phase-1 provisioning command plan."
            " Strictly non-mutating; there is no apply mode."
        ),
    )
    for flag, placeholder, help_text in DECISION_FLAGS:
        parser.add_argument(
            "--" + flag.replace("_", "-"),
            dest=flag,
            metavar=placeholder,
            help=help_text,
        )
    parser.add_argument(
        "--emit-shell",
        metavar="PATH",
        help=(
            "also write the reviewable fail-closed shell transcript"
            " (set -euo pipefail; C4 digest guard)"
        ),
    )
    parser.add_argument(
        "--plan-digest",
        action="store_true",
        help="print only sha256:<hex> of the canonicalized plan text",
    )
    args = parser.parse_args(argv)

    decisions = validate_decisions(
        {flag: getattr(args, flag) for flag, _, _ in DECISION_FLAGS}
    )

    if args.emit_shell:
        Path(args.emit_shell).write_text(render_shell(decisions), encoding="utf-8")
    if args.plan_digest:
        print(plan_digest(decisions))
    else:
        sys.stdout.write(canonical_plan_text(decisions))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
