# Main-machine runbook: validate on live Neo4j, then release

Do this on the machine that has the BloodHound CE / Neo4j container running.
It finishes the two things that needed a live Neo4j (the Bolt read and the
write-back), then publishes both projects.

## 0. What to move over

Copy just the two project folders. Do **not** copy any real `*_BloodHound.zip`
exports or lab data - they stay off the machine that publishes.

```
NoiseHound/     (the Python tool)
deadair/        (the Rust engine, sibling folder next to NoiseHound/)
```

## 1. Prerequisites

- Python 3.10+ and a Rust toolchain (`rustup`).
- The BloodHound CE stack running; Neo4j reachable on `bolt://localhost:7687`.
  Note the Neo4j credentials (BHCE default: `neo4j` / `bloodhoundcommunityedition`).
- Load a dataset into BloodHound (upload a SharpHound zip) so the graph exists.

## 2. Build / install

```bash
cd NoiseHound
python -m pip install -e ".[neo4j,sigma,test]"

cd ../deadair
cargo build --release          # NoiseHound auto-finds ../deadair/target/release
```

## 3. Validate the live Neo4j paths (the deferred checks)

```bash
export NEO4J_PASSWORD=bloodhoundcommunityedition   # match your compose

# a) Bolt read - confirm the graph loads live and coverage looks right
noisehound-inspect -i bolt://localhost:7687

# b) A real path query over the live graph (pick a real user + objective)
python -m noisehound -i bolt://localhost:7687 -s "someuser" -o "Domain Admins" -k 5

# c) Force the DeadAir engine to confirm the two-tier path works end to end
python -m noisehound -i bolt://localhost:7687 -s "someuser" -o "Domain Admins" --engine rust
```

Expected: inspect prints the node/edge histogram and corpus coverage; the path
queries return ranked paths; `--engine rust` gives identical results via DeadAir.

## 4. Write scores back into BloodHound (item 4)

```bash
# Stamp r.noise onto the BloodHound relationships
noisehound-writeback -i bolt://localhost:7687
```

Then in the BloodHound UI (or Neo4j browser) run the queries in
[`CYPHER.md`](CYPHER.md) - e.g. the noise-weighted APOC dijkstra quietest-path
query. You should see `noise` on edges and be able to find the quietest route to
Domain Admins visually. That is the BloodHound-native integration validated.

## 5. Publish

The repos already carry full git history (they ship with `.git`). Do **not**
`git init` - it would wipe that history. Create the GitHub repo, push the existing
history, then tag. You perform the credentialed steps (`gh auth login`,
`cargo login`, the PyPI publisher setup); nothing publishes without your action.

**NoiseHound -> GitHub + PyPI:**
```bash
cd NoiseHound
gh auth status                        # you: authenticate first if needed
gh repo create warpedatom/NoiseHound --public --source=. --remote=origin --push
git tag v1.0.0 && git push origin v1.0.0     # triggers the PyPI publish workflow
```
PyPI uses Trusted Publishing - on pypi.org configure the publisher for
`warpedatom/NoiseHound` (workflow `publish.yml`) *before* pushing the tag, or drop
a `PYPI_API_TOKEN` repo secret.

**DeadAir -> GitHub + crates.io:**
```bash
cd ../deadair
gh repo create warpedatom/DeadAir --public --source=. --remote=origin --push
git tag v0.2.0 && git push origin v0.2.0     # release workflow builds the binaries

cargo login                           # you: paste your crates.io API token
cargo publish --dry-run               # verify packaging, then:
cargo publish
```

## 6. Post-publish check

- CI green on both repos.
- DeadAir GitHub Release has the three binaries attached.
- `pip install noisehound` and `cargo install deadair` work from a clean box.
