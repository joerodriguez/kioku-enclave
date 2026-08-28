# `config/` map

This directory intentionally contains no runtime profile, backend selector, or PostgreSQL schema
mode. Production structured state is unconditionally PostgreSQL-authoritative, serving verifies
the required schema in code, and live large-media bytes use the one media-bucket binding selected
from the operator's external mode-0600 build file.

Do not add a SQLite/archive/witness toggle here. A future infrastructure coordinate may be
checked in only when it is part of the attested current architecture and has one fail-closed
parser, release-metadata binding, and deployment owner.
