# Sync DigiCert lego Fork with Upstream go-acme/lego

You are an expert Golang software engineer. Your job is to sync this DigiCert fork of lego (`github.com/digicert/lego`) with the latest upstream `go-acme/lego` repository, fix vulnerabilities, and raise a PR.

## Context

This repository is a DigiCert fork of [go-acme/lego](https://github.com/go-acme/lego) — the ACME v2 client library. The fork has intentional customizations that MUST be preserved during every sync.

**Upstream's default branch is `main`, not `master`.** Upstream `master` is stale (frozen mid-2026, hundreds of commits behind) and all releases since v5.0.0 come from `main`. Always sync from `main`. Confirm the latest release with the GitHub API rather than trusting local tags:

```bash
curl -s https://api.github.com/repos/go-acme/lego/releases/latest | grep -m1 '"tag_name"'
curl -s https://api.github.com/repos/go-acme/lego | grep '"default_branch"'
```

## ⚠️ Trap 1: global git `insteadOf` URL rewrites

This machine's **global** git config rewrites `github.com/go-acme/lego` to a personal fork:

```bash
git config --get-regexp 'url\.'
```

If that prints `url.https://github.com/<someone>/....insteadof https://github.com/go-acme/lego`, then **every `git fetch upstream` silently pulls the wrong repository** and you will conclude the fork is up to date when it is ~300 commits behind. Symptoms: `git ls-remote` returns only a handful of refs, and `upstream/master` looks older than your own fork.

Bypass it without editing the user's config by using the `www.` host, which does not prefix-match the rewrite rule:

```bash
git fetch https://www.github.com/go-acme/lego.git main:refs/temp/upstream_main
git log refs/temp/upstream_main -1 --oneline   # cross-check against the API sha
```

## DigiCert-Specific Changes (MUST PRESERVE)

1. **Module path**: `github.com/digicert/lego/v5` (upstream is `github.com/go-acme/lego/v5`). Bump the major suffix whenever upstream does — Go rejects a `vN` tag whose module path does not end in `/vN`.
2. **Raw keyAuth in `challenge/dns01/dns_challenge.go`**: `GetChallengeInfo()` returns the raw `keyAuth` string instead of `base64url(SHA256(keyAuth))`. Intentional deviation from RFC 8555.
3. **BlueCat Micetro DNS provider**: `providers/dns/bluecatmicetro/` — 6 files (client.go, client_test.go, dns.go, doc.go, errors.go, zone.go). Must also be registered in `providers/dns/zz_gen_dns_providers.go` (**import AND case statement** — the import is the one that goes missing).
4. **Enhanced DNS cleanup**: DigitalOcean, OVH, DreamHost, GoDaddy use an enumerate-then-delete pattern with `fmt.Printf`/`fmt.Println` debug statements instead of deleting by the record ID captured at `Present` time.
5. **Test expectations in `challenge/dns01/dns_challenge_test.go`**: `TestGetChallengeInfo*` expect the raw keyAuth (`"123"`), not the SHA256 hash.
6. **Generator template**: `internal/generators/dns/providers/dns_providers.go.tmpl` must use the `digicert` module path, or `make generate` silently reverts `zz_gen_dns_providers.go`.

The complete set of files with genuine (non-import-path) DigiCert changes is **17**. Everything else in the fork differs from upstream only by the module path. Verify that invariant — see Step 5.

## Step-by-Step Procedure

### Step 0: Toolchain

Check the `go` directive on upstream `main` and make sure a toolchain at least that new is on `PATH`. If Go is missing entirely, install it to a user-writable path (no sudo):

```bash
curl -s 'https://go.dev/dl/?mode=json' | grep -m1 '"version"'   # latest stable
# download go<VER>.darwin-arm64.tar.gz, VERIFY THE SHA256 from that JSON, extract to ~/sdk/go<VER>
export PATH="$HOME/sdk/go<VER>/bin:$PATH"
```

### Step 1: Fetch upstream `main`

Use the `www.` bypass from Trap 1. Do not rely on a pre-existing `upstream` remote.

### Step 2: Analyze divergence

```bash
U=refs/temp/upstream_main
git merge-base master $U
git rev-list --count master..$U                  # how far behind
git log master --not $U --oneline --no-merges    # DigiCert-only commits
```

Report the findings, the upstream release version, and **whether the module major version changed** before proceeding — a major bump breaks every downstream DigiCert consumer's imports and is the user's call.

### Step 3: Branch and merge

```bash
git checkout -b sync-upstream-<version>
git merge refs/temp/upstream_main --no-commit --no-ff -X theirs
```

Expect conflicts of type `UD` ("we modified, upstream deleted") for providers upstream removed or renamed. Confirm none of them carries DigiCert content, then accept the deletion:

```bash
git diff --name-only --diff-filter=U | xargs git rm -q --ignore-unmatch
```

### ⚠️ Trap 2: `-X theirs` silently mangles the DigiCert files

`-X theirs` does **not** cleanly take upstream's version — it interleaves hunks and produces code that references variables that no longer exist. Observed damage in past syncs: `dreamhost.go` and `digitalocean.go` kept a DigiCert loop but lost the `records, err := ...ListRecords(...)` line above it; `ovh.go` lost its `subDomain` declaration and ended up with a duplicate `reqURL :=`. **None of this appears as a merge conflict.** It only surfaces at compile time, and shallow checks like "is `fmt.Printf` still present?" will pass while the file is broken.

So: always re-derive the customizations against the new upstream code, and always compile.

### Step 4: Rewrite module paths

macOS `sed` needs an explicit empty argument to `-i`, and `|` cannot be the delimiter when the expression contains an alternation:

```bash
find . -type f \( -name '*.go' -o -name 'go.mod' -o -name '*.tmpl' -o -name '*.md' \) \
  -not -path './.git/*' -not -path './.claude/*' -not -path './.idea/*' -print0 \
| xargs -0 sed -i '' -E 's#github\.com/(go-acme|digicert)/lego/v[0-9]+#github.com/digicert/lego/v<N>#g'
```

Leave `go-acme` in doc URLs (`https://go-acme.github.io/...`, GitHub issue links) untouched — the `/vN` suffix in the pattern already excludes them. Verify:

```bash
grep -rn -E 'github\.com/go-acme/lego/v[0-9]' --exclude-dir=.git --exclude-dir=.claude --exclude-dir=.idea . | wc -l   # want 0
```

### Step 5: Audit for merge pollution

Every file **except** the 17 DigiCert ones must be byte-identical to upstream modulo the module path. This catches Trap 2 damage in files you weren't watching:

```bash
git ls-tree -r --name-only refs/temp/upstream_main | grep '\.go$' | while IFS= read -r f; do
  grep -qxF "$f" protect.txt && continue          # protect.txt = the 17 DigiCert files
  [ -f "$f" ] || continue
  git show "refs/temp/upstream_main:$f" \
    | sed -E 's#github\.com/(go-acme|digicert)/lego/v[0-9]+#github.com/digicert/lego/v<N>#g' \
    | diff -q - "$f" >/dev/null 2>&1 || echo "POLLUTED: $f"
done
```

Restore any polluted file from upstream (with the path rewrite applied). Then verify each of the 6 DigiCert customizations above by reading the actual code — not by grepping for a debug print.

### Step 6: Tidy, and fix packages upstream moved

```bash
go mod tidy
```

`go mod tidy` reporting `no matching versions for query "latest"` on a `github.com/digicert/lego/...` path means an internal package moved upstream and a DigiCert file still imports the old location. Past moves:

| old | new |
| --- | --- |
| `platform/config/env` | `platform/env` |
| `providers/dns/internal/useragent` | `internal/useragent` |

Also watch for interface changes: v5 added `ctx context.Context` as the first parameter of `challenge.Provider`'s `Present`/`CleanUp` and of `dns01.GetChallengeInfo`. DigiCert-only providers (bluecatmicetro) must be updated by hand.

### Step 7: Vulnerability scan

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

Record the count **before** the merge as well, using a worktree, so the PR can state what the sync actually fixed:

```bash
git worktree add --detach /tmp/wt-master master && (cd /tmp/wt-master && govulncheck ./...)
```

Remaining unreachable findings with `Fixed in: N/A` (e.g. `GO-2026-5932`, x/crypto/openpgp unmaintained) cannot be actioned — document them instead.

### Step 8: Build and test

```bash
go build ./... && go vet ./...
go test ./providers/dns/bluecatmicetro/... ./challenge/dns01/...
go test ./...
```

**Expected pre-existing failures:** the raw-keyAuth deviation makes every upstream provider test that asserts a hashed challenge value fail (they pass keyAuth `"123"`/`"123d=="` and expect `base64url(SHA256(...))`). This affects a large number of `providers/dns/*` packages and is **not** a regression. Prove it rather than assuming: re-run each failing package against pre-merge `master` and confirm it fails there too. Report any package that passed on `master` and fails after the merge as a real regression.

### Step 9: Commit

```bash
git add -A
git commit -m "chore: sync with upstream go-acme/lego <version> (<upstream-sha>)"
```

### Step 10: Push and open a PR against `master`

Title: `Sync with upstream go-acme/lego <version> and fix vulnerabilities`.
Body: upstream commits merged, new/removed/renamed providers, govulncheck before→after, the 6 DigiCert customizations confirmed preserved, and the known pre-existing test failures.

### Step 11: Report

1. Upstream commits merged — count and highlights
2. Provider changes — added, removed, renamed
3. DigiCert changes preserved — confirmation table
4. Vulnerability report — before/after counts and the unactionable remainder
5. Known deviations — the raw keyAuth deviation and its test fallout
6. Breaking changes for downstream consumers (module major version)
7. PR link
