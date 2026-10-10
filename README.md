# JunkDrawer — temporary AlgoX test bench

This is a **public, disposable CI workspace** for bounded AlgoX research tests. It is not the AlgoX repository, a deployed protocol, a production implementation, or a consensus security certification.

The test snapshot is reduced to the minimum Phase Zero Rust modules needed to exercise Experiment 023 and its existing regressions. It excludes private research specifications, historical archives, deployment credentials, production secrets, and unrelated experiments. Any test keys in source are **fixed, published demonstration fixtures** with no authority over the private AlgoX repository.

**Source reference:** private repository `iteathen/AlgoX`, exact research test source commit `865ae2fdedc63e53fa8b0c0ea7b01fc09e8c95f7`. The source files are an explicitly reduced **public test-only extraction**; the root module graph and Patricia-map adapter are pared down to required dependencies. All Experiment 023 source logic and test cases should be byte-identical to that commit.

Public GitHub Actions here test compiler and deterministic fixture behavior without using or checking out credentials for the private project. **Passing unit tests do not establish economic consensus, source theorem applicability, HAA, permissionless security, or live 40-node convergence.**

To run the public Rust tests locally:

```sh
cargo test --test pz_g1_genesis_event_trial
cargo test --test pz_g1_genesis_sync_trial --test pz_g1_chain_sync_observe --test pz_g1_consensus
```

**Latest verified public CI:** [run 38036073907](https://github.com/iteathen/JunkDrawer/actions/runs/38036073907) at source-matched public snapshot [`e182f34`](https://github.com/iteathen/JunkDrawer/commit/e182f3493eb10d8093bc7567d6929e048c487bf3) **PASSED 45/45 focused native Rust tests**: **17 event-driven Experiments 023–024**, **10 Genesis GSM/LoE/GDD**, **5 observed-header**, **13 deterministic PZ-G1 consensus** regressions, and `cargo check --lib`. No entire AlgoX private repository or private CI credentials were required.

**Bug found and corrected:** The first public run [38034796791](https://github.com/iteathen/JunkDrawer/actions/runs/38034796791) compiled successfully but failed 2 of 12 event tests: the source trial promoted `CaughtUp` using **proposed** GDD peer drops before the peers had actually been disconnected. AlgoX source [`89904ab`](https://github.com/iteathen/AlgoX/commit/89904ab42738519dd182d139fe0a44ced26f1b6d) requires that no unapplied GDD proposal remain before a caught-up transition and adds a thirteenth regression. The public snapshot mirrors that corrected source.

**Scope:** This is a reduced public test extraction with a pared-down Core module graph. It verifies those exact research modules and signed-history tests under Rust, **not** the complete private AlgoX crate, compiled WebAssembly, the native 40-process swarm, Ouroboros theorem correspondence, HAA or trustworthy canonical economic consensus. The private repo's GitHub-hosted Actions allowance remains exhausted.

**Experiment 024 source-density falsification:** [Red run 38035776231](https://github.com/iteathen/JunkDrawer/actions/runs/38035776231) compiled and ran 15 event tests, correctly exposing two failing assertions where proper-prefix histories improperly bypassed honest early-window Chain Growth (`13 PASS / 2 FAIL`). The private experimental source [`9a81560`](https://github.com/iteathen/AlgoX/commit/9a81560970b890ea1ffb6bafb9a2c40d4dfa1dad) now skips only **identical** histories, not shorter prefixes. [Green run 38035908718](https://github.com/iteathen/JunkDrawer/actions/runs/38035908718) passed all 15 event tests; the latest green run adds positive proper-prefix and full signed-rollback requalification controls for **17/17 event cases**. The [private Experiment 024 report](https://github.com/iteathen/AlgoX/blob/main/prototype/research/experiment-024-prefix-chain-growth-and-peer-reorganization.md) records the exact limited scope. Genuinely permissionless currentness and canonical economic consensus remain **unproved**.
