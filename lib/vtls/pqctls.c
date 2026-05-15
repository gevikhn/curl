/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * SPDX-License-Identifier: curl
 *
 * PQCTLS TLS backend for libcurl — post-quantum TLS via pqctls C API.
 *
 ***************************************************************************/
#include "curl_setup.h"

#ifdef USE_PQCTLS

#include <pqctls_capi.h>
#include <string.h>
#include <stdlib.h>

#include "urldata.h"
#include "curl_trc.h"
#include "vtls/vtls.h"
#include "vtls/vtls_int.h"
#include "vtls/pqctls.h"
#include "vtls/keylog.h"

/* Backend-specific per-connection data stored in connssl->backend. */
struct pqctls_ssl_backend_data {
  pqctls_ctx_t     *ctx;
  pqctls_session_t *session;
  BIT(data_in_pending);
  BIT(sent_shutdown);
};

/* Map pqctls error codes to CURLcode. */
static CURLcode pq_map_error(int rc)
{
  switch(rc) {
  case PQCTLS_OK:          return CURLE_OK;
  case PQCTLS_AGAIN:       return CURLE_AGAIN;
  case PQCTLS_ERR_NOMEM:   return CURLE_OUT_OF_MEMORY;
  case PQCTLS_ERR_CERT:    return CURLE_PEER_FAILED_VERIFICATION;
  case PQCTLS_ERR_TIMEOUT: return CURLE_OPERATION_TIMEDOUT;
  case PQCTLS_ERR_CLOSED:  return CURLE_RECV_ERROR;
  case PQCTLS_ERR_IO:      return CURLE_SEND_ERROR;
  default:                 return CURLE_SSL_CONNECT_ERROR;
  }
}

static void pq_refresh_data_pending(struct pqctls_ssl_backend_data *backend)
{
  backend->data_in_pending =
    (backend->session && pqctls_pending(backend->session) > 0) ? TRUE : FALSE;
}

static CURLcode pq_flush_pending_write(struct ssl_connect_data *connssl,
                                       struct Curl_easy *data,
                                       struct pqctls_ssl_backend_data *backend)
{
  size_t flushed = 0;
  int rc;

  if(!backend->session || !pqctls_want_write(backend->session))
    return CURLE_OK;

  rc = pqctls_write(backend->session, NULL, 0, &flushed);
  (void)flushed;
  if(rc == PQCTLS_OK) {
    if(pqctls_want_write(backend->session)) {
      connssl->io_need = CURL_SSL_IO_NEED_SEND;
      return CURLE_AGAIN;
    }
    return CURLE_OK;
  }
  if(rc == PQCTLS_AGAIN) {
    connssl->io_need = CURL_SSL_IO_NEED_SEND;
    return CURLE_AGAIN;
  }

  failf(data, "pqctls_write flush: %s", pqctls_strerror(rc));
  return pq_map_error(rc);
}

/* -- recv ------------------------------------------------------------ */

static CURLcode pq_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                        char *buf, size_t len, size_t *pnread)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct pqctls_ssl_backend_data *backend =
    (struct pqctls_ssl_backend_data *)connssl->backend;
  int rc;
  CURLcode result;

  DEBUGASSERT(backend && backend->session);
  *pnread = 0;
  connssl->io_need = CURL_SSL_IO_NEED_NONE;

  result = pq_flush_pending_write(connssl, data, backend);
  if(result != CURLE_OK) {
    backend->data_in_pending = FALSE;
    return result;
  }

  rc = pqctls_read(backend->session, buf, len, pnread);
  if(rc == PQCTLS_OK && *pnread > 0) {
    pq_refresh_data_pending(backend);
    return CURLE_OK;
  }
  if(rc == PQCTLS_AGAIN) {
    backend->data_in_pending = FALSE;
    connssl->io_need = pqctls_want_write(backend->session) ?
      CURL_SSL_IO_NEED_SEND : CURL_SSL_IO_NEED_RECV;
    return CURLE_AGAIN;
  }
  if(rc == PQCTLS_ERR_CLOSED) {
    connssl->peer_closed = TRUE;
    connssl->io_need = CURL_SSL_IO_NEED_NONE;
    return CURLE_OK;
  }
  failf(data, "pqctls_read: %s", pqctls_strerror(rc));
  return pq_map_error(rc);
}

/* -- send ------------------------------------------------------------ */

static CURLcode pq_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                        const void *buf, size_t len, size_t *pnwritten)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct pqctls_ssl_backend_data *backend =
    (struct pqctls_ssl_backend_data *)connssl->backend;
  int rc;

  DEBUGASSERT(backend && backend->session);
  *pnwritten = 0;
  connssl->io_need = CURL_SSL_IO_NEED_NONE;

  rc = pqctls_write(backend->session, buf, len, pnwritten);
  if(rc == PQCTLS_OK) {
    if(pqctls_want_write(backend->session))
      connssl->io_need = CURL_SSL_IO_NEED_SEND;
    return CURLE_OK;
  }
  if(rc == PQCTLS_AGAIN) {
    connssl->io_need = CURL_SSL_IO_NEED_SEND;
    return CURLE_AGAIN;
  }
  failf(data, "pqctls_write: %s", pqctls_strerror(rc));
  return pq_map_error(rc);
}

/* -- data_pending ---------------------------------------------------- */

static bool pq_data_pending(struct Curl_cfilter *cf,
                            const struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct pqctls_ssl_backend_data *backend =
    (struct pqctls_ssl_backend_data *)connssl->backend;
  (void)data;
  DEBUGASSERT(backend);
  if(backend->session && pqctls_pending(backend->session) > 0)
    backend->data_in_pending = TRUE;
  return (bool)backend->data_in_pending;
}

/* -- keylog ---------------------------------------------------------- */

static void pq_keylog_cb(const char *line, void *userdata)
{
  (void)userdata;
  Curl_tls_keylog_write_line(line);
}

/* -- connect --------------------------------------------------------- */

static CURLcode pq_connect(struct Curl_cfilter *cf, struct Curl_easy *data,
                           bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct pqctls_ssl_backend_data *backend =
    (struct pqctls_ssl_backend_data *)connssl->backend;
  const struct ssl_primary_config *conn_config =
    Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  curl_socket_t sock;
  int rc;

  DEBUGASSERT(backend);
  *done = FALSE;

  if(connssl->state == ssl_connection_complete) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* Get the underlying socket fd */
  sock = Curl_conn_cf_get_socket(cf->next, data);
  if(sock == CURL_SOCKET_BAD) {
    failf(data, "pqctls: no socket available");
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* Create context + session on first call */
  if(!backend->ctx) {
    int alg = PQCTLS_ALG_ECDSA_KYBER;
    char *env_alg = curl_getenv("PQCTLS_ALGORITHM");
    if(env_alg && strcmp(env_alg, "sm2") == 0)
      alg = PQCTLS_ALG_SM2_KYBER;
    free(env_alg);

    backend->ctx = pqctls_ctx_new(alg);
    if(!backend->ctx) {
      failf(data, "pqctls_ctx_new failed");
      return CURLE_SSL_CONNECT_ERROR;
    }

    /* Load CA cert */
    if(conn_config->ca_info_blob) {
      rc = pqctls_ctx_load_root_cert_mem(
        backend->ctx,
        (const uint8_t *)conn_config->ca_info_blob->data,
        conn_config->ca_info_blob->len);
      if(rc != PQCTLS_OK) {
        failf(data, "pqctls: failed to load CA cert blob: %s",
              pqctls_strerror(rc));
        return CURLE_SSL_CACERT_BADFILE;
      }
    }
    else if(conn_config->CAfile) {
      rc = pqctls_ctx_load_root_cert(backend->ctx, conn_config->CAfile);
      if(rc != PQCTLS_OK) {
        failf(data, "pqctls: failed to load CA cert '%s': %s",
              conn_config->CAfile, pqctls_strerror(rc));
        return CURLE_SSL_CACERT_BADFILE;
      }
    }

    /* Load client cert + key */
    if(conn_config->clientcert && ssl_config->key) {
      rc = pqctls_ctx_load_client_cert(backend->ctx,
                                       conn_config->clientcert,
                                       ssl_config->key);
      if(rc != PQCTLS_OK) {
        failf(data, "pqctls: failed to load client cert/key: %s",
              pqctls_strerror(rc));
        return CURLE_SSL_CERTPROBLEM;
      }
    }
    else if(conn_config->cert_blob && ssl_config->key_blob) {
      rc = pqctls_ctx_load_client_cert_mem(
        backend->ctx,
        (const uint8_t *)conn_config->cert_blob->data,
        conn_config->cert_blob->len,
        (const uint8_t *)ssl_config->key_blob->data,
        ssl_config->key_blob->len);
      if(rc != PQCTLS_OK) {
        failf(data, "pqctls: failed to load client cert/key blobs: %s",
              pqctls_strerror(rc));
        return CURLE_SSL_CERTPROBLEM;
      }
    }

    /* Create session */
    backend->session = pqctls_session_new(backend->ctx, (int)sock);
    if(!backend->session) {
      failf(data, "pqctls_session_new failed");
      return CURLE_SSL_CONNECT_ERROR;
    }

    /* Setup keylog */
    Curl_tls_keylog_open();
    if(Curl_tls_keylog_enabled()) {
      pqctls_set_keylog_callback(backend->session, pq_keylog_cb, NULL);
    }

    connssl->state = ssl_connection_negotiating;
  }

  /* Perform blocking handshake */
  rc = pqctls_connect_blocking(backend->session, 30000);
  if(rc != PQCTLS_OK) {
    failf(data, "pqctls handshake failed: %s", pqctls_strerror(rc));
    return pq_map_error(rc);
  }

  connssl->state = ssl_connection_complete;
  connssl->io_need = CURL_SSL_IO_NEED_NONE;
  *done = TRUE;

  {
    char verbuf[64];
    pqctls_version(verbuf, sizeof(verbuf));
    infof(data, "pqctls: handshake complete (%s)", verbuf);
  }

  return CURLE_OK;
}

/* -- shutdown -------------------------------------------------------- */

static CURLcode pq_shutdown(struct Curl_cfilter *cf, struct Curl_easy *data,
                            bool send_shutdown, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct pqctls_ssl_backend_data *backend =
    (struct pqctls_ssl_backend_data *)connssl->backend;

  (void)data;
  (void)send_shutdown;
  DEBUGASSERT(backend);

  if(!backend->session || cf->shutdown) {
    *done = TRUE;
    return CURLE_OK;
  }

  pqctls_shutdown(backend->session);
  *done = TRUE;
  cf->shutdown = TRUE;
  return CURLE_OK;
}

/* -- close ----------------------------------------------------------- */

static void pq_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct pqctls_ssl_backend_data *backend =
    (struct pqctls_ssl_backend_data *)connssl->backend;

  (void)data;
  DEBUGASSERT(backend);

  if(backend->session) {
    pqctls_session_free(backend->session);
    backend->session = NULL;
  }
  if(backend->ctx) {
    pqctls_ctx_free(backend->ctx);
    backend->ctx = NULL;
  }
}

/* -- get_internals --------------------------------------------------- */

static void *pq_get_internals(struct ssl_connect_data *connssl, CURLINFO info)
{
  struct pqctls_ssl_backend_data *backend =
    (struct pqctls_ssl_backend_data *)connssl->backend;
  (void)info;
  DEBUGASSERT(backend);
  return backend->session;
}

/* -- version --------------------------------------------------------- */

static size_t pq_version(char *buffer, size_t size)
{
  return pqctls_version(buffer, size);
}

/* -- vtable ---------------------------------------------------------- */

const struct Curl_ssl Curl_ssl_pqctls = {
  { CURLSSLBACKEND_PQCTLS, "pqctls" },    /* info */
  SSLSUPP_CAINFO_BLOB,                     /* supports */
  sizeof(struct pqctls_ssl_backend_data),

  NULL,                            /* init */
  NULL,                            /* cleanup */
  pq_version,                      /* version */
  pq_shutdown,                     /* shutdown */
  pq_data_pending,                 /* data_pending */
  NULL,                            /* random */
  NULL,                            /* cert_status_request */
  pq_connect,                      /* connect */
  Curl_ssl_adjust_pollset,         /* adjust_pollset */
  pq_get_internals,                /* get_internals */
  pq_close,                        /* close_one */
  NULL,                            /* close_all */
  NULL,                            /* set_engine */
  NULL,                            /* set_engine_default */
  NULL,                            /* engines_list */
  NULL,                            /* sha256sum */
  pq_recv,                         /* recv decrypted data */
  pq_send,                         /* send data to encrypt */
  NULL,                            /* get_channel_binding */
};

#endif /* USE_PQCTLS */
