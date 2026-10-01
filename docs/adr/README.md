# Architecture decision records

This ledger records architecture decisions owned by `sidestr-rs`. Estate policy
and deployment decisions remain in their owning repositories; these records link
to them where they set a boundary for this workspace.

Three status axes are independent:

- **decision** says whether this repository has adopted the design;
- **implementation** says how much of the source change exists;
- **activation** says whether an estate chain or service uses it.

Source parity, crate publication and estate activation are separate claims. A
published crate can therefore be complete while its activation remains inactive.

1. [ADR-0001](ADR-0001-reference-oracle-is-the-compatibility-contract.md):
   the pinned reference is the compatibility oracle (`accepted / complete / live`).
2. [ADR-0002](ADR-0002-keep-optional-execution-and-services-behind-crate-boundaries.md):
   optional execution and services stay behind crate boundaries
   (`accepted / complete / inactive`).
3. [ADR-0003](ADR-0003-keep-reserve-attestations-origin-neutral-and-private.md):
   reserve attestations stay origin-neutral and project-private
   (`accepted / complete / inactive`).

Copy [TEMPLATE.md](TEMPLATE.md) for a new record. Update this index and the root
README in the same change when a decision changes a public boundary.
