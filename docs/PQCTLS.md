<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# PQCTLS

curl can be built with the PQCTLS backend through the pqctls C API wrapper.
This backend is currently intended for client-side use only and is available
through the CMake build.

For the generic CMake build flow, see [INSTALL-CMAKE.md](INSTALL-CMAKE.md).
This document focuses on the extra pieces needed to build and use curl with
PQCTLS.
For downstream maintenance guidance, see
[PQCTLS-MAINTAINING.md](PQCTLS-MAINTAINING.md).

## Prerequisites

Prepare a pqctls install prefix that provides these files:

- `include/pqctls_capi.h`
- `lib/libpqctls_capi.a`
- `lib/libpqctls_handshake.a`
- `lib/libpqctls_codec.a`
- `lib/libpqctls_crypto.a`
- `lib/libpqc_certs.a`

You also need the Tongsuo or OpenSSL installation used when building pqctls,
so curl can link `libcrypto` consistently with the pqctls static libraries.

## Build With PQCTLS Only

Configure curl with PQCTLS as the only TLS backend:

```sh
cmake -B ../curl-build-pqctls \
  -DCURL_USE_PQCTLS=ON \
  -DCURL_USE_OPENSSL=OFF \
  -DPQCTLS_ROOT_DIR=/path/to/pqctls-prefix \
  -DPQCTLS_TONGSUO_DIR=/path/to/tongsuo-install \
  -DCURL_USE_LIBPSL=OFF

cmake --build ../curl-build-pqctls
```

## Build In A MultiSSL Configuration

PQCTLS can be combined with another supported TLS backend in a MultiSSL build.
For example, to build with both OpenSSL and PQCTLS:

```sh
cmake -B ../curl-build-multissl-pqctls \
  -DCURL_USE_OPENSSL=ON \
  -DCURL_USE_PQCTLS=ON \
  -DPQCTLS_ROOT_DIR=/path/to/pqctls-prefix \
  -DPQCTLS_TONGSUO_DIR=/path/to/tongsuo-install \
  -DCURL_DEFAULT_SSL_BACKEND=pqctls

cmake --build ../curl-build-multissl-pqctls
```

If PQCTLS is not the default backend, or if you want to override the default
at runtime, set:

```sh
export CURL_SSL_BACKEND=pqctls
```

In a MultiSSL build, `curl --version` lists the enabled backends in the
`libcurl` line. When PQCTLS is the active backend, that line includes a
`pqctls/...` version string.

## Certificate Inputs

The PQCTLS backend expects PQCTLS binary credential files, not PEM files. The
typical inputs are:

- `root_cert.bin` for `--cacert`
- `client_cert.bin` for `--cert`
- `client_sk.bin` for `--key`

## Running curl With PQCTLS

A typical request against a local pqctls proxy looks like this:

```sh
curl \
  --noproxy '*' \
  --cacert /path/to/root_cert.bin \
  --cert /path/to/client_cert.bin \
  --key /path/to/client_sk.bin \
  https://127.0.0.1:9000/size/1024
```

`--noproxy '*'` is recommended for local validation so environment variables
such as `https_proxy` do not silently route the request through another proxy.

To switch the PQCTLS certificate algorithm at runtime, set:

```sh
export PQCTLS_ALGORITHM=sm2
```

The default is `ecdsa`.
