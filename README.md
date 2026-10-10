# JunkDrawer — temporary AlgoX test bench

This is a **public, disposable CI workspace** for bounded AlgoX research tests. It is not the AlgoX repository, a deployed protocol, a production implementation, or a consensus security certification.

The test snapshot is reduced to the minimum Phase Zero Rust modules needed to exercise Experiment 023 and its existing regressions. It excludes private research specifications, historical archives, deployment credentials, production secrets, and unrelated experiments. Any test keys in source are **fixed, published demonstration fixtures** with no authority over the private AlgoX repository.

**Source reference:** private repository `iteathen/AlgoX`, exact development commit `dce8b5c2fa56f509331fe014afa028cd9d103a0e`. The source files are an explicitly reduced **public test-only extraction**; the root module graph and Patricia-map adapter are pared down to required dependencies. All Experiment 023 source logic and test cases should be byte-identical to that commit.

Public GitHub Actions here test compiler and deterministic fixture behavior without using or checking out credentials for the private project. **Passing unit tests do not establish economic consensus, source theorem applicability, HAA, permissionless security, or live 40-node convergence.**

To run the public Rust tests locally:

```sh
cargo test --test pz_g1_genesis_event_trial
cargo test --test pz_g1_genesis_sync_trial --test pz_g1_chain_sync_observe --test pz_g1_consensus
```
