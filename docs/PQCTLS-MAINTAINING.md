<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Maintaining the PQCTLS patch stack

This repository carries PQCTLS as a downstream patch stack on top of curl.
Keep the branch linear and keep each commit focused so the stack can be
rebased onto future curl release tags with minimal conflict resolution.

## Maintenance rules

- Base PQCTLS work on official curl release tags such as `curl-8_19_0`.
- Do not track release candidate tags such as `rc-8_20_0-1`.
- Keep the `pqctls` branch as a linear patch stack. Do not merge `master` into
  `pqctls`.
- Keep non-PQCTLS changes out of the branch. Upstreamable fixes should live in
  separate branches.
- Prefer updating existing PQCTLS commits over adding cross-cutting fixup
  commits. A short stack is easier to replay.

## Patch order

Keep the branch in this order:

1. `cmake: add PQCTLS build and backend identifiers`
2. `vtls: add PQCTLS backend implementation`
3. `docs: document building and using PQCTLS`
4. `docs: add PQCTLS maintenance guide`

The earlier commits carry code and build integration. The later commits carry
operator-facing documentation. Keeping this order makes conflicts easier to
localize when curl changes its TLS plumbing or CMake layout.

## Rebasing to a new release

Fetch upstream tags first:

```sh
git fetch upstream --tags
git tag -l 'curl-[0-9]*' --sort=-creatordate | head
```

Then rebase the stack from the old release tag to the new one:

```sh
git switch pqctls
git rebase --onto <new-release-tag> <old-release-tag> pqctls
```

Example:

```sh
git switch pqctls
git rebase --onto curl-8_20_0 curl-8_19_0 pqctls
```

If you prefer to validate on a throwaway branch first:

```sh
git switch -c pqctls-update curl-8_20_0
git cherry-pick <commit1>^..<commit4>
```

After validation, fast-forward or force-update `pqctls` to the tested stack.

## Conflict hotspots

When a rebase stops, inspect these files first:

- `CMakeLists.txt`
- `include/curl/curl.h`
- `lib/curl_setup.h`
- `lib/curl_config-cmake.h.in`
- `lib/vtls/vtls.c`
- `lib/vtls/keylog.c`
- `lib/vtls/pqctls.c`

These files are where curl upstream most often changes TLS backend selection,
backend registration, or VTLS callback contracts.

## Validation checklist

Run at least these checks after every rebase:

1. Configure a PQCTLS-only build.
2. Configure a MultiSSL build with PQCTLS selected by
   `-DCURL_DEFAULT_SSL_BACKEND=pqctls`.
3. Verify `curl --version` reports the expected backend list and active
   `pqctls/...` version string.
4. Run the sample command from [PQCTLS.md](PQCTLS.md) against a known-good
   PQCTLS endpoint.
5. Repeat the runtime check with `CURL_SSL_BACKEND=pqctls`.
6. Repeat once with `PQCTLS_ALGORITHM=sm2` if that mode is still supported by
   the linked pqctls build.

If pqctls or Tongsuo changes ABI or file layout, update both
[PQCTLS.md](PQCTLS.md) and the CMake detection logic in the same series.

## Exporting the stack

To archive or hand off the downstream changes as mail-ready patches:

```sh
git format-patch <release-tag>..pqctls
```

This is useful when the stack needs review outside the repository or when a
rebase should be tested in a clean clone.
