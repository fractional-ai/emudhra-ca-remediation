# Verifying what is deployed

A merged PR is not a fix. A system is patched when **the artifact that is actually
running** rejects the compromised chains. For each deployed system, work through
three steps:

1. **Identify the running artifact.** Use an image digest, a function version, a
   binary, or a host, never a tag or a branch name.
2. **Inspect it.** Run `probe_runtime.sh` inside it (live), or copy its filesystem,
   bundles and binaries out and check them offline (`trust_store.py`,
   `go_binaries.py`, and `scan_repo.py --all`, which finds the affected
   certificates and keys in any file, binaries included).
3. **Record the evidence** next to the digest or version you checked.

If the live probe exits 2 (INCONCLUSIVE: no egress, an intercepting proxy, no
client found), fall back to the offline checks. Don't mark a system SAFE on an
inconclusive probe, and don't mark it SAFE on any check that did not exit 0.

Run probes against staging, or against a one-off copy of the production artifact
(`docker run` of the same digest), when you can. Never deploy to production
that belongs to someone else, or restart it, without its owner's go-ahead.
`kubectl exec` into a running pod is read-only in effect, but get the owner's OK
first for clusters you don't own anyway.

## Containers in general

```bash
# Run the exact digest that is deployed, not the tag
docker run --rm -i --entrypoint sh IMAGE@sha256:DIGEST -s < scripts/probe_runtime.sh

# Distroless / scratch (no shell): copy the filesystem out and inspect offline
cid=$(docker create IMAGE@sha256:DIGEST) && mkdir -p fs && docker export "$cid" | tar -x -C fs && docker rm "$cid"
python3 scripts/trust_store.py --root fs system java python   # the stores this image has; NONE rows don't count
python3 scripts/go_binaries.py --root fs fs   # Go binaries; --root resolves symlinks inside fs
python3 scripts/scan_repo.py --all fs --no-info   # every file: bundles, keystores, embedded roots

# Or run the live probe in a shell-less image: add busybox in a throwaway layer.
# Its applets go last on PATH, so the image's own clients are the ones tested.
# Busybox's wget is removed: it does not verify certificates, so it is not the
# image's client and could only fail the run.
# The applets are made in the busybox stage, so nothing runs as the image's own
# (often non-root) user during the build, and the probe still runs as that user.
docker build -q -t probe-tmp - <<'EOF'
FROM busybox:musl AS bb
RUN mkdir /bb && cp /bin/busybox /bb/ && /bb/busybox --install -s /bb && rm -f /bb/wget /bb/ssl_client /bb/nc
FROM IMAGE@sha256:DIGEST
COPY --from=bb /bb /bb
EOF
docker run --rm -i --entrypoint /bb/sh probe-tmp -c 'PATH="$PATH:/bb" sh -s' < scripts/probe_runtime.sh
docker rmi probe-tmp
```

`probe_runtime.sh` tests the interpreters on `PATH` (or `PROBE_PYTHON` /
`PROBE_NODE`), with their default trust. It does **not** test: an app's venv
unless you point `PROBE_PYTHON` at it, botocore's vendored bundle, httpx or SDKs
that pick their own store, Playwright or Puppeteer's Chromium, Node bundled in a
Python wheel, a CI runner's internal Node, or a cloud CLI's frozen Python. For
those, check the bundle with `trust_store.py` or `scan_repo.py --all`, or run a
request through that exact client.

Base image freshness: `docker inspect IMAGE@sha256:DIGEST --format '{{.Created}}'`.
An image built before 2026-10-20 cannot have a fixed distro `ca-certificates`.

## Kubernetes (EKS, GKE, AKS, self-managed)

```bash
# Every running image, by digest, across namespaces
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{range .status.containerStatuses[*]}{.imageID}{" "}{end}{"\n"}{end}' | sort -u -k3
# Probe one pod per distinct image
kubectl exec -i -n NS POD -c CONTAINER -- sh -s < scripts/probe_runtime.sh
```

Include init containers, sidecars (service mesh proxies, log shippers), CronJobs,
and operators. After the rollout, check that `imageID` changed on **every** replica.
Old ReplicaSets and `imagePullPolicy: IfNotPresent` with a reused tag are classic
misses.

## AWS

- **ECS / Fargate**: `aws ecs describe-tasks` lists `containers[].imageDigest` for
  running tasks. Compare it with the patched digest, then `docker run` that digest
  with the probe.
- **Lambda**: the runtime is AWS-managed and patched by AWS on their schedule, but
  certifi, botocore and requests in your **deployment package and layers** are
  yours. Download the package (`aws lambda get-function --query Code.Location`), unzip
  it, and run `scan_repo.py --all` on the unzipped tree: it finds every bundle,
  whatever it is called, and judges the pinned packages. For container-image
  functions, treat the image like any other container. Check
  `aws lambda get-function-configuration` to see the runtime version.
- **EC2 / AMIs**: probe through SSM Run Command (`sh -s` is not available, so copy
  the script in first) or SSH. Rebuild golden AMIs, or patched instances will
  regress on the next scale-out.
- **Elastic Beanstalk, App Runner, Batch**: map each to its image or platform version,
  then do as above.

## Google Cloud

- **Cloud Run**: `gcloud run services describe SVC --format='value(status.latestReadyRevisionName)'`,
  then `gcloud run revisions describe REV --format='value(spec.containers[0].image)'`.
  It prints a digest. `docker run` that digest with the probe.
- **Cloud Functions (gen2)** are Cloud Run underneath: same approach. Vendored
  certifi is yours to fix, and the runtime base is Google's to patch.
- **GKE**: see Kubernetes. **GCE**: as for EC2.

## Azure

- **Container Apps / App Service (containers)**: `az containerapp revision list` and
  `az webapp config show` give the image. Probe that digest.
- **Functions / App Service (code)**: the platform runtime is Microsoft's. Check the
  dependencies you ship, then use the Kudu/SSH console to run the probe.

## Managed runtimes: Vercel, Netlify, Lambda, Cloud Functions, Cloud Run buildpacks

**A managed runtime that hasn't been probed from inside is VULNERABLE.** The
platform picks the runtime's patch version, and nothing in the repo or the build
log proves which one runs: on one Vercel project, `engines.node` said 24 and
production ran Node 24.21.0, which accepted 6 of the 12 test chains. "The
platform patches it" is a hope until the probe below says so.

Platform **builds** ignore repo pins too. A Vercel build ran Bun 1.3.14
although `package.json` said `"packageManager": "bun@1.4.4"`. Build steps
often run database migrations or uploads with production credentials, so check
what the build image actually runs (print `bun --version` / `node --version` in
the build command), and treat the build environment as a system of its own: its
secrets went over whatever client it had.

`engines.node` (Vercel, Netlify) and the project's Node setting pick only the
**major**. Changing either changes production's major version, so that is a
deploy decision for the project owner, not a scan fix.

### Probe from inside the runtime

1. On a branch, add a throwaway function or route that runs the probe inside the
   runtime and returns the runtime version and a verdict per host:

   ```js
   // app/api/emudhra-probe/route.js (Next.js); any function shape works
   const kinds = ["dv", "ov", "ev"], gens = ["g3b", "g3c"], vias = ["", "-aaa"];
   const hosts = kinds.flatMap(k => gens.flatMap(g => vias.map(v => `${k}-${g}${v}-emudhra.we-have-a-problem.com`)));
   const TRUST = new Set(["UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
     "SELF_SIGNED_CERT_IN_CHAIN", "DEPTH_ZERO_SELF_SIGNED_CERT", "CERT_UNTRUSTED", "CERT_REJECTED"]);
   export async function GET() {
     const out = {};
     for (const h of hosts) {
       try { await fetch(`https://${h}/`, { cache: "no-store" }); out[h] = "ACCEPTED"; }
       catch (e) { const c = e?.cause?.code || e?.code || String(e); out[h] = TRUST.has(c) ? "ok" : `INCONCLUSIVE ${c}`; }
     }
     return Response.json({ runtime: process.version, hosts: out });
   }
   ```

   Only a refusal for a **trust** reason counts. A timeout, DNS failure or
   `CERT_HAS_EXPIRED` says nothing about whether the chain is trusted, so it is
   INCONCLUSIVE, and so is any host missing from the output. Send no credentials
   to these hosts.
2. Deploy it as a **preview**, never to production, and call it. The runtime is
   fixed only if all 12 hosts show `ok`. For Python functions, do the same with
   `requests.get` (certifi) and `urllib.request` (`ssl`), and report both.
3. Delete the route and the preview. Production deployments built before the
   platform shipped its patch keep the old runtime until a redeploy, so redeploy
   production and probe again, with the project owner's go-ahead if it is not
   yours.

If the runtime fails and can't be upgraded yet, ship the Node stopgap in
`remediation.md` (drop the affected roots at startup), probe again, and record
the system as exposed-with-mitigation, not fixed. Vendored bundles in the
function code are yours either way: download the deployment package and run
`scan_repo.py --all` on it.

- **Cloudflare Workers** use Cloudflare's own TLS stack for `fetch()`, and
  Cloudflare handles it. The probe above still settles it.

## Fly.io, Render, Railway, Heroku

These are image-based (Fly, Render, Railway) or buildpack-based (Heroku). Find
the release's image or slug, then rebuild **with the build cache cleared**:
`fly deploy --no-cache`, Render's "Clear build cache & deploy", Heroku
`heroku builds:cache:purge`. Then probe through `fly ssh console` or
`heroku run sh -s`.

## CI/CD runners and build systems

- Probe each pipeline image or runner pool once, from a throwaway branch or a
  draft PR that is never merged. That covers the network path for package
  installs and deploy credentials. Don't leave the probe in the repo's CI.
- **Hosted GitHub runners are not all patched.** `ubuntu-latest` (24.04 and 26.04)
  shipped `ca-certificates 20260601`, which accepts the 6 emSign chains, and jobs
  in one run can land on old and new images. The fixed package
  (`20260816ubuntu0.24.04.1`, `.26.04.1`) is published, and `--only-upgrade`
  installs it on today's runners. ubuntu24 images from `20261021` on ship it;
  `20261012` does not, and was still being served alongside them on 2026-10-22.
  Until no job lands on an older image, make this the **first** step of every
  job, before `actions/checkout`, which sends `GITHUB_TOKEN`. Each job's "Set up
  job" log prints its image version. Remove the step only after a probe on a
  throwaway branch, run several times, never lands on an image older than
  `20261021`:

  ```yaml
  - run: sudo apt-get update && sudo apt-get install -y --only-upgrade ca-certificates
  ```

  The runner's own Node (`externals/node24`) runs JavaScript actions and their
  OIDC credential exchanges. It was 24.21.0 until runner v2.338.1 (2026-10-22),
  which bundles 24.22.1. `NODE_OPTIONS` set
  through `GITHUB_ENV` is rejected, but set in the workflow's or job's `env:` it
  works. Confirmed in CI, this made it refuse all 12 chains:

  ```yaml
  env:
    NODE_OPTIONS: --use-openssl-ca
    SSL_CERT_FILE: /etc/ssl/certs/ca-certificates.crt
  ```

  Add it only to jobs that exchange credentials through a JavaScript action (OIDC
  to a cloud, registry logins). It is temporary: remove it once every job's
  "Set up job" log shows runner version 2.338.1 or later. `scan_repo.py` flags hosted-runner jobs without the upgrade step.
- `actions/setup-node` with a floating version (`24`, `lts/*`) uses the runner's
  cached Node unless `check-latest: true` is set. Pin the exact fixed version.
- A repo with no CI is verified the same way as any other: run the scripts
  against its lockfile, its built artifact and its deployed runtime, and record
  the result. Don't add CI or a test to it for this.
- Self-hosted GitHub runners, ARC images, GitLab runners, Buildkite agents and
  Jenkins agents need their host and image patched, and the tools themselves
  (pip, uv, Node, JDK, Go CLIs) must be the fixed versions. Their package caches
  are only as trustworthy as the hashes that guard them: lockfile integrity
  (npm, pnpm, yarn, Go sums, Cargo, `pip --require-hashes`) catches a tampered
  download, but Maven, Gradle and unhashed pip installs take whatever the
  connection served. On a runner that was exposed on a network you don't
  control, clear those caches.

## Other platforms that pick their own runtime

- **Lambda managed runtimes**: read `RuntimeVersionConfig` from
  `aws lambda get-function-configuration`; the runtime's patch level is AWS's.
  Probe from inside a test invocation, as for Vercel.
- **Vercel Python functions and Edge Middleware** are separate runtimes from
  Vercel's Node functions. Probe each one you use.
- **EC2 hosts**: the fix belongs in `user_data` or the AMI, or the next
  scale-out regresses.
- **Agent and sandbox environments** whose image follows a package version
  (a `base:<version>` image, snapshots keyed on a tag that survive no-cache
  rebuilds): rebuild the snapshot itself, then probe inside it.
- **Vendor images with no patched tag on your major**: replacing the Node binary
  with the one from `node:24.22.1-alpine` has worked. Check that native addons
  still load, and keep it as a mitigation until the vendor ships.
- **Verification without credentials**: compare a reproducible build with the
  deployed artifact's hash (Lambda `CodeSha256`, an image digest), or read the
  version and commit from a public health endpoint.

## Desktop and mobile apps you ship

- **Electron**: ship a build on 44.9.1, 43.8.1 or 42.11.16, then check the version
  your auto-update channel is actually serving.
- **iOS / Android**: apps on the platform TLS stack are covered by OS updates and
  CT (iOS, and Android 14+ with Play system updates). Apps that bundle their own
  roots (OkHttp with a custom `TrustManager`, Flutter/Dart `SecurityContext`, a
  vendored cacert) need a release. So do apps with WebViews on Android 13 and
  older. Mobile backends: treat them as servers above.

## Developer and staff laptops

Run `probe_runtime.sh` locally, on macOS especially, after applying the macOS
steps in `remediation.md`. All 12 chains must show `ok` for curl, Python, and Node,
both in a new shell and with the environment cleared (`env -i HOME="$HOME"
PATH=/usr/bin:/bin`), since launchd jobs, GUI apps and cron never read the
shell's variables. Then cover what the probe on PATH doesn't reach: every
runtime a version manager keeps, and every binary that embeds a runtime (see
"Version managers" and "Binaries that embed a runtime" in `remediation.md`).
Record each runtime's version as it reports it, never a file's mtime.

## Evidence to record per system

| Field | Example |
|---|---|
| System | `acme-api` (owner: Acme platform team), prod, us-east-1 |
| Artifact | `ghcr.io/acme/api@sha256:3f1c…`, built 2026-10-22 |
| Trust sources | Debian 13 ca-certificates, certifi (requests), Node 24 sidecar |
| Before | ca-certificates 20250419+deb13u0, certifi 2026.7.22: VULNERABLE (6/12 chains) |
| Fix | PR link, deploy ID |
| After | probe exit 0: 12/12 refused by curl, python ssl, python certifi, node; trust_store.py system CLEAN |
| Status | SAFE / VULNERABLE / NEEDS OWNER (with who and why) |
