# Sync DigiCert lego Fork with Upstream go-acme/lego

You are an expert Golang software engineer. Your job is to sync this DigiCert fork of lego (`github.com/digicert/lego`) with the latest upstream `go-acme/lego` repository, fix vulnerabilities, and raise a PR.

## Context

This repository is a DigiCert fork of [go-acme/lego](https://github.com/go-acme/lego) — the ACME v2 client library. The fork has intentional customizations that MUST be preserved during every sync.

## DigiCert-Specific Changes (MUST PRESERVE)

1. **Module path**: `github.com/digicert/lego/v4` (not `go-acme/lego/v4`)
2. **Raw keyAuth in `challenge/dns01/dns_challenge.go`**: `GetChallengeInfo()` returns raw `keyAuth` string instead of `base64url(SHA256(keyAuth))`. This is an intentional deviation from ACME RFC 8555.
3. **BlueCat Micetro DNS provider**: `providers/dns/bluecatmicetro/` — 6 files (client.go, client_test.go, dns.go, doc.go, errors.go, zone.go). Must also be registered in `providers/dns/zz_gen_dns_providers.go` (import + case statement).
4. **Enhanced DNS cleanup in providers**: DigitalOcean, OVH, DreamHost, GoDaddy — use enumerate-then-delete pattern with `fmt.Printf` debug statements. Keep these.
5. **Test expectations in `challenge/dns01/dns_challenge_test.go`**: `TestGetChallengeInfo*` tests expect raw keyAuth value (e.g. `"123"`) not SHA256 hash.

## Step-by-Step Procedure

### Step 1: Setup upstream remote
```bash
git remote add upstream https://github.com/go-acme/lego 2>/dev/null || true
git fetch upstream master
```

### Step 2: Analyze divergence
```bash
# Find common ancestor
git merge-base master upstream/master

# List new upstream commits
git log upstream/master --not master --oneline --no-merges

# Count the gap
git rev-list --count master..upstream/master

# List DigiCert-only commits
git log master --not upstream/master --oneline --no-merges
```

Report the divergence findings to the user.

### Step 3: Create a new branch and merge upstream
```bash
git checkout -b fix_vulnerability_and_update_upstream
git merge upstream/master --no-commit --no-ff -X theirs
```

If there are merge conflicts, resolve them by preferring upstream for most files.

### Step 4: Bulk-fix module import paths
Replace all `go-acme` import paths with `digicert` in Go files:
```bash
find . -name "*.go" ! -path "./.claude/*" ! -path "./vendor/*" \
  -exec sed -i 's|github.com/go-acme/lego/v4|github.com/digicert/lego/v4|g' {} \;
```

Also fix non-Go files (README.md, CHANGELOG.md):
```bash
sed -i 's|go-acme/lego|digicert/lego|g' README.md CHANGELOG.md
```

**IMPORTANT**: Leave `go-acme/lego` references in code COMMENTS and GitHub URLs untouched — only replace import paths and module references.

Verify no Go import paths remain with `go-acme`:
```bash
grep -rn "go-acme/lego" --include="*.go" . | grep -v "//.*https\?://" | grep "import\|\"github"
```

### Step 5: Verify DigiCert-specific changes survived

Check each one explicitly:

```bash
# 1. Raw keyAuth preserved
grep -A5 "func GetChallengeInfo" challenge/dns01/dns_challenge.go

# 2. BlueCat Micetro provider intact
ls providers/dns/bluecatmicetro/
grep "bluecatmicetro" providers/dns/zz_gen_dns_providers.go

# 3. Debug prints in providers
grep "fmt.Printf" providers/dns/digitalocean/digitalocean.go
grep "listTXTRecords" providers/dns/ovh/ovh.go
```

If the `bluecatmicetro` import is missing from `zz_gen_dns_providers.go`, add it in alphabetical order after `bluecatv2`:
```go
"github.com/digicert/lego/v4/providers/dns/bluecatmicetro"
```

If `dns_challenge_test.go` has SHA256 hash expectations (like `"pmWkWSBCL51Bfkhn79xPuKBKHz__H6B-mY6G9_eieuM"`), replace them with the raw keyAuth value (e.g. `"123"`) and add a comment: `// DigiCert fork: raw keyAuth (no SHA256/base64url)`.

### Step 6: Run go mod tidy
```bash
go mod tidy
```

### Step 7: Run vulnerability scan
```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

If vulnerabilities are found:
- For Go stdlib vulns: bump the `go` directive in `go.mod` to the fixed version
- For `golang.org/x/net`: update the version in `go.mod`
- Run `go mod tidy` again after changes

### Step 8: Build and test
```bash
# Build core packages (use -p 1 if OOM occurs on full build)
go build -p 1 ./acme/... ./certificate/... ./challenge/... ./cmd/...
go build -p 1 ./providers/dns/bluecatmicetro/...

# Test DigiCert-specific packages
go test -p 1 ./providers/dns/bluecatmicetro/...
go test -p 1 -run "TestGetChallengeInfo" ./challenge/dns01/
```

### Step 9: Commit all changes
```bash
git add -A
# Exclude .claude/ directory
git reset HEAD .claude/ 2>/dev/null

git commit -m "chore: sync with upstream go-acme/lego through <version> (<upstream-sha>)

- Merged N upstream commits
- Preserved DigiCert module path (github.com/digicert/lego/v4)
- Preserved BlueCat Micetro DNS provider
- Preserved intentional DNS challenge keyAuth deviation
- Preserved enhanced provider cleanup logic
- Fixed N govulncheck vulnerabilities

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

### Step 10: Push and create PR
```bash
git push origin fix_vulnerability_and_update_upstream
```

Create a PR targeting `master` with:
- Title: `Sync with upstream go-acme/lego <version> and fix vulnerabilities`
- Body: List new providers, bug fixes merged, vulnerabilities fixed, and DigiCert changes preserved

### Step 11: Report to user

Produce a summary report covering:
1. **Upstream commits merged** — count and highlights
2. **New DNS providers added** — list them
3. **DigiCert changes preserved** — confirmation table
4. **Vulnerability report** — govulncheck findings and fixes applied
5. **Known deviations** — document the raw keyAuth deviation
6. **PR link**
