# xmip-core-identify-contract

Identify by contract: the Contract the first section is bound to, presented as a detected claim that names no Party. A technology of [xmip-core-identify](https://github.com/IlleNilsson/xmip-core-identify).

A binding is a statement about the content's shape, and anyone who can
produce the shape can produce the binding, so the claim is the Contract's
name and never a Party. Who the content is from is what its sender proved;
where a Contract is agreed with a Party, `xmip-core-authorize-contract`
compares that Party with the one the sender proved and refuses another
(the owner, 2026-11-10; ADR-0019, amendment 2026-11-11).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

`cargo test`: four tests — the bound Contract is a detected claim naming no
Party; a section bound to none, and a Message with no section, present
nothing; a binding with no name is an error. The included workflow is
manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
