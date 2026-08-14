# Single-archive WAL owner child map

| Path | Purpose |
|---|---|
| `publisher.rs` | Private inactive publisher/checkpoint implementation. It consumes the maintenance WAL handoff, durably owns the exact witness lease, stages logical WAL objects through Control, and performs bounded two-pass checkpoint source retirement, reserve/create/readback recovery, exact witness advance, and fresh recovered-owner settlement. It exposes no production domain codec, launcher, route, Store factory, acknowledgement, list/delete operation, or startup/config/runtime activation. |
