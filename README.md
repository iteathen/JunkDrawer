# JunkDrawer — temporary AlgoX test bench

This is a **public, disposable CI workspace** for bounded AlgoX research tests. It is not the AlgoX repository, a deployed protocol, a production implementation, or a consensus security certification.

The test snapshot is reduced to the minimum Phase Zero Rust modules needed to exercise Experiment 023 and its existing regressions. It excludes private research specifications, historical archives, deployment credentials, production secrets, and unrelated experiments. Any test keys in source are **fixed, published demonstration fixtures** with no authority over the private AlgoX repository.

**Source reference:** private repository `iteathen/AlgoX`, exact development commit `89904ab42738519dd182d139fe0a44ced26f1b6d`. The source files are an explicitly reduced **public test-only extraction**; the root module graph and Patricia-map adapter are pared down to required dependencies. All Experiment 023 source logic and test cases should be byte-identical to that commit.

Public GitHub Actions here test compiler and deterministic fixture behavior without using or checking out credentials for the private project. **Passing unit tests do not establish economic consensus, source theorem applicability, HAA, permissionless security, or live 40-node convergence.**

To run the public Rust tests locally:

```sh
cargo test --test pz_g1_genesis_event_trial
cargo test --test pz_g1_genesis_sync_trial --test pz_g1_chain_sync_observe --test pz_g1_consensus
```

**Verified public CI:** [run 38035113088](https://github.com/iteathen/JunkDrawer/actions/runs/38035113088) at JunkDrawer commit `77f36677ffcffe644f85ace7fe964145cba50298` **PASSED** all **41** independent Rust tests: **13 Experiment 023 event-state cases**, **10 Genesis source-sync cases**, **5 observed-header cases** and **13 deterministic PZ-G1 consensus cases**, followed by `cargo check --lib`.

**Bug found and corrected:** The first public run [38034796791](https://github.com/iteathen/JunkDrawer/actions/runs/38034796791) compiled successfully but failed 2 of 12 event tests: the source trial promoted `CaughtUp` using **proposed** GDD peer drops before the peers had actually been disconnected. AlgoX source [`89904ab`](https://github.com/iteathen/AlgoX/commit/89904ab42738519dd182d139fe0a44ced26f1b6d) requires that no unapplied GDD proposal remain before a caught-up transition and adds a thirteenth regression. The public snapshot mirrors that corrected source.

**Scope:** This is a reduced public test extraction with a pared-down Core module graph. It verifies those exact research modules and signed-history tests under Rust, **not** the complete private AlgoX crate, compiled WebAssembly, the native 40-process swarm, Ouroboros theorem correspondence, HAA or trustworthy canonical economic consensus. The private repo's GitHub-hosted Actions allowance remains exhausted.
