# Single-archive WAL owner child map

| Path | Purpose |
|---|---|
| `launcher.rs` | Private inactive composition owner. It consumes only the parity-certified completed maintenance handoff, owns one heterogeneous sealed-plan actor for the archive, and never exposes or clones the actor handle. There is no caller, startup/config/route/Store-registry/acknowledgement wiring, provider list/delete authority, deployment, or cloud mutation. |
| `publisher.rs` | Private inactive publisher/checkpoint implementation. It is called only by the private sibling launcher after the parity-certified maintenance handoff is reauthenticated, durably owns the exact witness lease, stages logical WAL objects through Control, and performs bounded two-pass checkpoint source retirement, reserve/create/readback recovery, exact witness advance, and fresh recovered-owner settlement. It exposes no external domain adapter, route, Store factory, acknowledgement, list/delete operation, or startup/config/runtime activation. |
