/*
 * This file is part of trinarkular
 *
 * Copyright (C) 2015 The Regents of the University of California.
 * Authors: Alistair King
 *
 * This software is Copyright (c) 2015 The Regents of the University of
 * California. All Rights Reserved. Permission to copy, modify, and distribute this
 * software and its documentation for academic research and education purposes,
 * without fee, and without a written agreement is hereby granted, provided that
 * the above copyright notice, this paragraph and the following three paragraphs
 * appear in all copies. Permission to make use of this software for other than
 * academic research and education purposes may be obtained by contacting:
 *
 * Office of Innovation and Commercialization
 * 9500 Gilman Drive, Mail Code 0910
 * University of California
 * La Jolla, CA 92093-0910
 * (858) 534-5815
 * invent@ucsd.edu
 *
 * This software program and documentation are copyrighted by The Regents of the
 * University of California. The software program and documentation are supplied
 * "as is", without any accompanying services from The Regents. The Regents does
 * not warrant that the operation of the program will be uninterrupted or
 * error-free. The end-user understands that the program was developed for research
 * purposes and is advised not to rely exclusively on the program for any reason.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST
 * PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE. THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS
 * IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATIONS TO PROVIDE
 * MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 *
 * Report any bugs, questions or comments to alistair@caida.org
 *
 */

#include "trinarkular_probelist.h"
#include "trinarkular.h"
#include "trinarkular_log.h"
#include "config.h"
#include "khash.h"
#include "utils.h"
#include "wandio_utils.h"
#include "jsmn_utils.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <wandio.h>

KHASH_INIT(32s24, uint32_t, trinarkular_slash24_t, 1, kh_int_hash_func,
           kh_int_hash_equal);

KHASH_INIT(32state, uint32_t, trinarkular_slash24_state_t, 1, kh_int_hash_func,
           kh_int_hash_equal);

struct trinarkular_probelist {

  /** Current probelist version */
  char *version;

  /** List of /24s in this probelist */
  uint32_t *slash24s;

  /** Number of /24s in this probelist */
  int slash24s_cnt;

  /** Index of the current /24 */
  int slash24_iter;

  /** Signals provided (see trinarkular_probelist_get_signals) */
  uint8_t signals;

  /** Buffer for deserializing /24s into */
  // trinarkular_slash24_t slash24;

  /** Buffer for deserializing state into */
  // trinarkular_slash24_state_t state;

  // Normally stored in redis:

  /** Hash mapping from network IP to /24 */
  khash_t(32s24) * s24_hash;

  /** Hash mapping from network IP to state */
  khash_t(32state) * state_hash;
};

/* ---------- PRIVATE FUNCTIONS ---------- */

static int copy_state(trinarkular_slash24_state_t *to,
                      trinarkular_slash24_state_t *from)
{
  int i;

  for (i = 0; i < TRINARKULAR_SIGNAL_CNT; i++) {
    to->sig[i] = from->sig[i];
  }
  to->cumulative_rtt = from->cumulative_rtt;
  to->probes_sent = from->probes_sent;
  to->replies_seen = from->replies_seen;
  to->latency_kp_index = from->latency_kp_index;
  to->loss_kp_index = from->loss_kp_index;
  to->probes_kp_index = from->probes_kp_index;

  // realloc metrics array
  if ((to->metrics =
         realloc(to->metrics, sizeof(trinarkular_slash24_metrics_t) *
                                from->metrics_cnt * TRINARKULAR_SIGNAL_CNT)) ==
      NULL) {
    return -1;
  }

  // copy metrics
  for (i = 0; i < from->metrics_cnt * TRINARKULAR_SIGNAL_CNT; i++) {
    to->metrics[i] = from->metrics[i];
  }

  to->metrics_cnt = from->metrics_cnt;

  return 0;
}

static void free_state(trinarkular_slash24_state_t *state)
{
  if (state == NULL) {
    return;
  }

  free(state->metrics);
  state->metrics = 0;
}

static int add_host(trinarkular_slash24_t *s24, int proto, uint32_t host_ip,
                    uint16_t port)
{
  trinarkular_slash24_hosts_t *h = &s24->proto[proto];

  assert((host_ip & TRINARKULAR_SLASH24_NETMASK) == s24->network_ip);

  uint8_t host_byte = host_ip & TRINARKULAR_SLASH24_HOSTMASK;

  if ((h->hosts = realloc(h->hosts, sizeof(uint8_t) * (h->hosts_cnt + 1))) ==
      NULL) {
    return -1;
  }
  h->hosts[h->hosts_cnt] = host_byte;

  if (proto != TRINARKULAR_PROBE_PROTO_ICMP) {
    if ((h->ports = realloc(h->ports, sizeof(uint16_t) * (h->hosts_cnt + 1))) ==
        NULL) {
      return -1;
    }
    h->ports[h->hosts_cnt] = port;
  }

  h->hosts_cnt++;

  return 0;
}

/** Shuffle a protocol's hosts, keeping each host with its port */
static void shuffle_hosts(trinarkular_slash24_hosts_t *h)
{
  int i, r;
  uint8_t host;
  uint16_t port;

  for (i = h->hosts_cnt - 1; i > 0; i--) {
    r = rand() % (i + 1);
    host = h->hosts[i];
    h->hosts[i] = h->hosts[r];
    h->hosts[r] = host;
    if (h->ports != NULL) {
      port = h->ports[i];
      h->ports[i] = h->ports[r];
      h->ports[r] = port;
    }
  }
}

static int add_metadata(trinarkular_slash24_t *s24, char *md)
{
  // 2019-12-19 AK: changed this from an assert to warning since we
  // now have 2 /24s with >255 metas. They appear to be VPN networks
  // or some such.
  if (s24->md_cnt == UINT8_MAX) {
    trinarkular_log("WARN: Dropping metadata for /24 (%x)", s24->network_ip);
    return 0;
  }

  if ((s24->md = realloc(s24->md, sizeof(char *) * (s24->md_cnt + 1))) ==
      NULL) {
    return -1;
  }
  if ((s24->md[s24->md_cnt] = strdup(md)) == NULL) {
    return -1;
  }

  // this is an 8bit field to save memory
  assert(s24->md_cnt < UINT8_MAX);
  s24->md_cnt++;

  return 0;
}

static trinarkular_slash24_t *add_slash24(trinarkular_probelist_t *pl,
                                          uint32_t network_ip)
{
  khiter_t k;
  int khret;
  trinarkular_slash24_t *s24 = NULL;

  assert((network_ip & TRINARKULAR_SLASH24_NETMASK) == network_ip);

  // first, add to the list of /24s
  if ((pl->slash24s = realloc(
         pl->slash24s, sizeof(uint32_t) * (pl->slash24s_cnt + 1))) == NULL) {
    return NULL;
  }
  pl->slash24s[pl->slash24s_cnt++] = network_ip;

  // FILE ONLY
  // now add to the map
  k = kh_put(32s24, pl->s24_hash, network_ip, &khret);
  if (khret == -1) {
    trinarkular_log("ERROR: Could not add /24 to probelist");
    return NULL;
  }

  // init all the fields
  s24 = &kh_val(pl->s24_hash, k);

  s24->network_ip = network_ip;
  memset(s24->proto, 0, sizeof(s24->proto));
  s24->md = NULL;
  s24->md_cnt = 0;

  return s24;
}

// DOES NOT FREE THE /24 structure
static void free_slash24(trinarkular_slash24_t *s24)
{
  int i;

  if (s24 == NULL) {
    return;
  }

  for (i = 0; i < TRINARKULAR_PROBE_PROTO_CNT; i++) {
    free(s24->proto[i].hosts);
    s24->proto[i].hosts = NULL;
    free(s24->proto[i].ports);
    s24->proto[i].ports = NULL;
    s24->proto[i].hosts_cnt = 0;
  }

  for (i = 0; i < s24->md_cnt; i++) {
    free(s24->md[i]);
    s24->md[i] = NULL;
  }

  free(s24->md);
  s24->md = NULL;
}

#if 0
static void
destroy_slash24(trianrkular_slash24_t *s24)
{
  free_slash24(s24);
  free(s24);
}
#endif

static jsmntok_t *process_json_host(trinarkular_probelist_t *pl,
                                    trinarkular_slash24_t *s24, int proto,
                                    char *json, jsmntok_t *t)
{
  int cnt = 0;
  int i;
  char host_str[INET_ADDRSTRLEN];
  uint32_t host_ip;
  int host_ip_set = 0;
  unsigned long port = 0;
  int port_set = 0;

  jsmn_type_assert(t, JSMN_OBJECT);
  cnt = t->size;
  JSMN_NEXT(t);

  for (i = 0; i < cnt; i++) {
    // key
    jsmn_type_assert(t, JSMN_STRING);
    if (jsmn_streq(json, t, "host_ip")) {
      JSMN_NEXT(t);
      jsmn_type_assert(t, JSMN_STRING);
      jsmn_strcpy(host_str, t, json);
      inet_pton(AF_INET, host_str, &host_ip);
      host_ip = ntohl(host_ip);
      host_ip_set = 1;
      JSMN_NEXT(t);
    } else if (jsmn_streq(json, t, "e_b")) {
      JSMN_NEXT(t);
      jsmn_type_assert(t, JSMN_PRIMITIVE);
      // ignore response rate field
      JSMN_NEXT(t);
    } else if (jsmn_streq(json, t, "port")) {
      JSMN_NEXT(t);
      jsmn_type_assert(t, JSMN_PRIMITIVE);
      if (jsmn_strtoul(&port, json, t) != 0 || port == 0 || port > UINT16_MAX) {
        trinarkular_log("ERROR: Invalid port in host object");
        goto err;
      }
      port_set = 1;
      JSMN_NEXT(t);
    } else {
      // ignore all other fields
      JSMN_NEXT(t);
      // skip the value
      t = jsmn_skip(t);
    }
  }

  if (host_ip_set == 0) {
    trinarkular_log("ERROR: Missing field in host object");
    goto err;
  }

  // every non-ICMP host needs the port it is probed on
  if (proto != TRINARKULAR_PROBE_PROTO_ICMP && port_set == 0) {
    trinarkular_log("ERROR: Missing port in host object (%s)", host_str);
    goto err;
  }

  if (add_host(s24, proto, host_ip, port) != 0) {
    trinarkular_log("ERROR: Could not add host to /24 (%s)", host_str);
    goto err;
  }

  return t;

err:
  return NULL;
}

/** Fields shared by a /24 record in the single-protocol format and by each
 * entry of "protocols" in the multi-protocol format */
struct hostset_fields {
  unsigned long host_cnt;
  int host_cnt_set;
  int avg_resp_rate_set;
  int host_arr_cnt;
};

/** Parse one hostset field (host_cnt, avg_resp_rate or hosts) at t.
 * @return pointer to the next token, t unchanged if the key is not a hostset
 * field, or NULL on error */
static jsmntok_t *process_json_hostset_field(trinarkular_probelist_t *pl,
                                             trinarkular_slash24_t *s24,
                                             int proto, char *json,
                                             jsmntok_t *t,
                                             struct hostset_fields *f)
{
  trinarkular_slash24_hosts_t *h = &s24->proto[proto];
  double avg_resp_rate = 0;
  int j;

  if (jsmn_streq(json, t, "host_cnt")) {
    JSMN_NEXT(t);
    jsmn_type_assert(t, JSMN_PRIMITIVE);
    if (jsmn_strtoul(&f->host_cnt, json, t) != 0) {
      trinarkular_log("ERROR: Could not parse host count");
      goto err;
    }
    f->host_cnt_set = 1;
    JSMN_NEXT(t);

  } else if (jsmn_streq(json, t, "avg_resp_rate")) {
    JSMN_NEXT(t);
    jsmn_type_assert(t, JSMN_PRIMITIVE);
    if (jsmn_strtod(&avg_resp_rate, json, t) != 0) {
      trinarkular_log("ERROR: Could not parse avg resp rate");
      goto err;
    }
    h->aeb = avg_resp_rate;
    f->avg_resp_rate_set = 1;
    JSMN_NEXT(t);

  } else if (jsmn_streq(json, t, "hosts")) {
    JSMN_NEXT(t);
    jsmn_type_assert(t, JSMN_ARRAY);
    f->host_arr_cnt = t->size; // number of host objects
    JSMN_NEXT(t);
    for (j = 0; j < f->host_arr_cnt; j++) {
      if ((t = process_json_host(pl, s24, proto, json, t)) == NULL) {
        goto err;
      }
    }

    // now randomize the ordering
    shuffle_hosts(h);
  }

  return t;

err:
  return NULL;
}

static int hostset_fields_check(struct hostset_fields *f)
{
  if (f->host_cnt_set == 0 || f->avg_resp_rate_set == 0 ||
      f->host_arr_cnt == 0) {
    return -1;
  }
  // final sanity check
  assert(f->host_arr_cnt == f->host_cnt);
  return 0;
}

/** Parse the "protocols" object of a multi-protocol /24 record */
static jsmntok_t *process_json_protocols(trinarkular_probelist_t *pl,
                                         trinarkular_slash24_t *s24,
                                         char *json, jsmntok_t *t)
{
  int proto_cnt, field_cnt;
  int i, j, proto;
  jsmntok_t *next;
  struct hostset_fields f;

  jsmn_type_assert(t, JSMN_OBJECT);
  proto_cnt = t->size;
  JSMN_NEXT(t);

  for (i = 0; i < proto_cnt; i++) {
    jsmn_type_assert(t, JSMN_STRING);
    if (jsmn_streq(json, t, "icmp")) {
      proto = TRINARKULAR_PROBE_PROTO_ICMP;
    } else if (jsmn_streq(json, t, "tcp")) {
      proto = TRINARKULAR_PROBE_PROTO_TCP;
    } else {
      trinarkular_log("WARN: Unrecognized protocol: %.*s", t->end - t->start,
                      json + t->start);
      JSMN_NEXT(t);
      t = jsmn_skip(t);
      continue;
    }
    JSMN_NEXT(t);

    jsmn_type_assert(t, JSMN_OBJECT);
    field_cnt = t->size;
    JSMN_NEXT(t);
    memset(&f, 0, sizeof(f));
    for (j = 0; j < field_cnt; j++) {
      jsmn_type_assert(t, JSMN_STRING);
      if ((next = process_json_hostset_field(pl, s24, proto, json, t, &f)) ==
          NULL) {
        goto err;
      }
      if (next == t) {
        trinarkular_log("WARN: Unrecognized key: %.*s", t->end - t->start,
                        json + t->start);
        JSMN_NEXT(t);
        next = jsmn_skip(t);
      }
      t = next;
    }
    if (hostset_fields_check(&f) != 0) {
      trinarkular_log("ERROR: Missing field in protocol record");
      goto err;
    }
    pl->signals |= TRINARKULAR_SIGNAL_BIT(proto);
  }

  pl->signals |= TRINARKULAR_SIGNAL_BIT(TRINARKULAR_SIGNAL_COMBINED);

  return t;

err:
  return NULL;
}

/* A /24 record is either in the original single-protocol format, whose
 * host_cnt, avg_resp_rate and hosts are ICMP:
 *
 *   {"version": ..., "meta": [...],
 *    "host_cnt": N, "avg_resp_rate": A, "hosts": [{"host_ip": ...}, ...]}
 *
 * or in the multi-protocol format, with the same three fields per protocol,
 * and a port on every non-ICMP host:
 *
 *   {"version": ..., "meta": [...],
 *    "protocols": {
 *      "icmp": {"host_cnt": N, "avg_resp_rate": A, "hosts": [...]},
 *      "tcp":  {"host_cnt": N, "avg_resp_rate": A,
 *               "hosts": [{"host_ip": ..., "port": 80}, ...]}}}
 */
static jsmntok_t *process_json_slash24(trinarkular_probelist_t *pl,
                                       char *s24_str, char *json,
                                       jsmntok_t *root_tok)
{
  jsmntok_t *t = root_tok + 1;
  jsmntok_t *next;
  int i, j;

  char *tmp;
  trinarkular_slash24_t *s24 = NULL;
  uint32_t network_ip = 0;

  char str_tmp[1024];

  struct hostset_fields icmp;
  int protocols_set = 0;

  int meta_cnt = 0;
  int meta_set = 0;

  memset(&icmp, 0, sizeof(icmp));

  // first, add the /24 so that as we parse we can update it directly

  // parse the /24 string into a network ip
  if ((tmp = strchr(s24_str, '/')) == NULL) {
    trinarkular_log("ERROR: Malformed /24 string: %s", s24_str);
    goto err;
  }
  *tmp = '\0';
  inet_pton(AF_INET, s24_str, &network_ip);
  network_ip = ntohl(network_ip);

  // add to the probelist
  if ((s24 = add_slash24(pl, network_ip)) == NULL) {
    goto err;
  }

  // iterate over children of the /24 object
  for (i = 0; i < root_tok->size; i++) {
    // all keys must be strings
    if (t->type != JSMN_STRING) {
      fprintf(stderr, "ERROR: Encountered non-string key: '%.*s'\n",
              t->end - t->start, json + t->start);
      goto err;
    }
    // trinarkular_log("INFO: key: '%.*s'", t->end - t->start, json+t->start);

    // version
    if (jsmn_streq(json, t, "version")) {
      JSMN_NEXT(t);
      jsmn_type_assert(t, JSMN_STRING);
      if (pl->version == NULL) { // assume all version strings are the same
        jsmn_strcpy(str_tmp, t, json);
        pl->version = strdup(str_tmp);
        assert(pl->version != NULL);
      }
      JSMN_NEXT(t);

      // meta
    } else if (jsmn_streq(json, t, "meta")) {
      JSMN_NEXT(t);
      jsmn_type_assert(t, JSMN_ARRAY);
      meta_cnt = t->size; // number of meta strings
      JSMN_NEXT(t);
      for (j = 0; j < meta_cnt; j++) {
        jsmn_type_assert(t, JSMN_STRING);
        jsmn_strcpy(str_tmp, t, json);
        if (add_metadata(s24, str_tmp) != 0) {
          goto err;
        }
        JSMN_NEXT(t);
      }
      meta_set = 1;

      // multi-protocol format
    } else if (jsmn_streq(json, t, "protocols")) {
      JSMN_NEXT(t);
      if ((t = process_json_protocols(pl, s24, json, t)) == NULL) {
        goto err;
      }
      protocols_set = 1;

    } else {
      // single-protocol format: host_cnt, avg_resp_rate, hosts are ICMP
      if ((next = process_json_hostset_field(
             pl, s24, TRINARKULAR_PROBE_PROTO_ICMP, json, t, &icmp)) == NULL) {
        goto err;
      }
      if (next == t) {
        // unknown key
        trinarkular_log("WARN: Unrecognized key: %.*s", t->end - t->start,
                        json + t->start);
        JSMN_NEXT(t);
        next = jsmn_skip(t);
      }
      t = next;
    }
  }

  if (pl->version == NULL || meta_set == 0) {
    trinarkular_log("ERROR: Missing field in /24 record");
    goto err;
  }

  if (protocols_set != 0) {
    if (icmp.host_cnt_set || icmp.avg_resp_rate_set || icmp.host_arr_cnt) {
      trinarkular_log("ERROR: /24 record mixes single- and multi-protocol "
                      "fields");
      goto err;
    }
  } else {
    if (hostset_fields_check(&icmp) != 0) {
      trinarkular_log("ERROR: Missing field in /24 record");
      goto err;
    }
    pl->signals |= TRINARKULAR_SIGNAL_BIT(TRINARKULAR_SIGNAL_ICMP);
  }

  return t;

err:
  return NULL;
}

// This will eventually be used to parse a blob from redis, with some
// modifications (like not parsing the /24 key)
static int process_json(trinarkular_probelist_t *pl, char *js, int jslen)
{
  int ret;

  jsmn_parser p;
  jsmntok_t *root = NULL;
  jsmntok_t *t = NULL;
  size_t tokcount = 128;

  char s24_str[INET_ADDRSTRLEN + 3];

  if (jslen == 0) {
    trinarkular_log("ERROR: Empty JSON");
    return 0;
  }

  // prepare parser
  jsmn_init(&p);

  // allocate some tokens to start
  if ((root = malloc(sizeof(jsmntok_t) * tokcount)) == NULL) {
    trinarkular_log("ERROR: Could not malloc initial tokens");
    goto err;
  }

again:
  if ((ret = jsmn_parse(&p, js, jslen, root, tokcount)) < 0) {
    if (ret == JSMN_ERROR_NOMEM) {
      tokcount *= 2;
      if ((root = realloc(root, sizeof(jsmntok_t) * tokcount)) == NULL) {
        trinarkular_log("ERROR: Could not realloc tokens");
        goto err;
      }
      goto again;
    }
    if (ret == JSMN_ERROR_INVAL) {
      trinarkular_log("ERROR: Invalid character in JSON string");
      goto err;
    }
    trinarkular_log("ERROR: JSON parser returned %d", ret);
    goto err;
  }

  t = root;

  if (t->type != JSMN_STRING) {
    trinarkular_log("ERROR: Malformed /24 object\n");
    trinarkular_log("INFO: JSON: %s\n", js);
    goto err;
  }
  jsmn_strcpy(s24_str, t, js);
  // trinarkular_log("INFO: Processing /24: '%s'", s24_str);
  // move to the value
  JSMN_NEXT(t);

  if ((t = process_json_slash24(pl, s24_str, js, t)) == NULL) {
    goto err;
  }

  free(root);
  return 0;

err:
  trinarkular_log("ERROR: Invalid JSON probelist");
  free(root);
  return -1;
}

static int read_file(trinarkular_probelist_t *pl, const char *filename)
{
  io_t *infile = NULL;

  int ret;
#define BUFSIZE 1024
  char *js = NULL;
  int js_alloc = BUFSIZE;
  int jslen = 0;
  char buf[1024];
  char *bufp;
  char *bufend = buf + BUFSIZE;

  enum {
    OUTER_OPEN,
    S24,
  } state = OUTER_OPEN;
  int obj_start = 0;
  int obj_end = 0;

  // just be sure we're reading into a clean probelist
  assert(pl->version == NULL && trinarkular_probelist_get_slash24_cnt(pl) == 0);

  if ((infile = wandio_create(filename)) == NULL) {
    trinarkular_log("ERROR: Could not open %s for reading\n", filename);
    goto err;
  }

  if ((js = malloc(js_alloc)) == NULL) {
    fprintf(stderr, "ERROR: Could not allocate JSON string buffer\n");
    goto err;
  }

  // need to manually extract each /24 object so that we can do stream parsing
  while ((ret = wandio_read(infile, buf, BUFSIZE)) > 0) {
    bufp = buf;

    switch (state) {
    case OUTER_OPEN:
      // skip chars until we find '{'
      while (bufp < bufend && *bufp != '{') {
        bufp++;
      }
      if (bufp == bufend) {
        // read the next buffer
        continue;
      }
      if (*bufp == '{') {
        state = S24;
        obj_start = 0;
        obj_end = 0;
        bufp++;
      }
    // fall through

    case S24:
      // copy until we have seen at least one '{' and then a matching number of
      // '}'. if we see a '}' before any '{' then the json is over
      while (bufp < bufend) {
        // copy into json string
        if (jslen == js_alloc) {
          js_alloc *= 2;
          if ((js = realloc(js, js_alloc)) == NULL) {
            fprintf(stderr, "ERROR: Could not reallocate JSON string buffer\n");
            goto err;
          }
        }
        js[jslen++] = *bufp;

        switch (*bufp) {
        case '{':
          obj_start++;
          break;

        case '}':
          if (obj_start == 0) {
            // end of json
            goto done;
          }
          obj_end++;
          if (obj_start == obj_end) {
            // hand js off to /24 processing
            if (process_json(pl, js, jslen) != 0) {
              goto err;
            }
            obj_start = 0;
            obj_end = 0;
            jslen = 0;
          }
          break;

        default:
          break;
        }
        bufp++;
      }
    }
  }
  if (ret < 0) {
    trinarkular_log("WARN: Reading from JSON file failed");
    trinarkular_log("WARN: Probelist may be incomplete");
  }

done:
  free(js);
  if (infile != NULL) {
    wandio_destroy(infile);
  }
  return 0;

err:
  free(js);
  if (infile != NULL) {
    wandio_destroy(infile);
  }
  return -1;
}

/* ---------- PUBLIC FUNCTIONS ---------- */

trinarkular_probelist_t *trinarkular_probelist_create(const char *filename)
{
  trinarkular_probelist_t *pl = NULL;

  trinarkular_log("INFO: Creating probelist from %s", filename);

  if ((pl = malloc_zero(sizeof(trinarkular_probelist_t))) == NULL) {
    return NULL;
  }

  // FILE-SPECIFIC
  if ((pl->s24_hash = kh_init(32s24)) == NULL) {
    trinarkular_log("ERROR: Could not allocate /24 map");
    goto err;
  }
  if ((pl->state_hash = kh_init(32state)) == NULL) {
    trinarkular_log("ERROR: Could not allocate state map");
    goto err;
  }

  // read the probelist in from the file
  if (read_file(pl, filename) != 0) {
    trinarkular_log("ERROR: Could not load probelist from file");
    goto err;
  }

  // randomize the /24s
  array_shuffle_fy(uint32_t, pl->slash24s, pl->slash24s_cnt);

  return pl;

err:
  trinarkular_probelist_destroy(pl);
  return NULL;
}

void trinarkular_probelist_destroy(trinarkular_probelist_t *pl)
{
  khiter_t k;

  if (pl == NULL) {
    return;
  }

  free(pl->version);
  pl->version = NULL;

  free(pl->slash24s);
  pl->slash24s = NULL;
  pl->slash24s_cnt = 0;

  if (pl->s24_hash != NULL) {
    for (k = kh_begin(pl->s24_hash); k < kh_end(pl->s24_hash); k++) {
      if (kh_exist(pl->s24_hash, k) != 0) {
        free_slash24(&kh_val(pl->s24_hash, k));
      }
    }
    kh_destroy(32s24, pl->s24_hash);
    pl->s24_hash = NULL;
  }

  if (pl->state_hash != NULL) {
    for (k = kh_begin(pl->state_hash); k < kh_end(pl->state_hash); k++) {
      if (kh_exist(pl->state_hash, k) != 0) {
        free_state(&kh_val(pl->state_hash, k));
      }
    }
    kh_destroy(32state, pl->state_hash);
    pl->state_hash = NULL;
  }

  free(pl);
}

char *trinarkular_probelist_get_version(trinarkular_probelist_t *pl)
{
  return pl->version;
}

uint8_t trinarkular_probelist_get_signals(trinarkular_probelist_t *pl)
{
  return pl->signals;
}

int trinarkular_probelist_get_slash24_cnt(trinarkular_probelist_t *pl)
{
  return pl->slash24s_cnt;
}

void trinarkular_probelist_reset_slash24_counters(trinarkular_probelist_t *pl)
{
  khiter_t k;
  trinarkular_slash24_state_t *state;

  if (pl == NULL) {
    return;
  }

  if (pl->state_hash != NULL) {
    for (k = kh_begin(pl->state_hash); k < kh_end(pl->state_hash); k++) {
      if (kh_exist(pl->state_hash, k) != 0) {
        state = &(kh_val(pl->state_hash, k));
        state->cumulative_rtt = 0;
        state->probes_sent = 0;
        state->replies_seen = 0;
      }
    }
  }
}

void trinarkular_probelist_reset_slash24_iter(trinarkular_probelist_t *pl)
{
  pl->slash24_iter = 0;
}

trinarkular_slash24_t *
trinarkular_probelist_get_next_slash24(trinarkular_probelist_t *pl)
{
  trinarkular_slash24_t *s24 = NULL;

  if (trinarkular_probelist_has_more_slash24(pl) == 0) {
    return NULL;
  }

  // FILE SPECIFIC IMPLEMENTATION
  s24 = trinarkular_probelist_get_slash24(pl, pl->slash24s[pl->slash24_iter]);
  // END

  pl->slash24_iter++;

  return s24;
}

int trinarkular_probelist_has_more_slash24(trinarkular_probelist_t *pl)
{
  return (pl->slash24_iter < pl->slash24s_cnt);
}

trinarkular_slash24_t *
trinarkular_probelist_get_slash24(trinarkular_probelist_t *pl,
                                  uint32_t network_ip)
{
  trinarkular_slash24_t *s24 = NULL;
  khiter_t k;

  // FILE SPECIFIC IMPLEMENTATION
  if ((k = kh_get(32s24, pl->s24_hash, network_ip)) == kh_end(pl->s24_hash)) {
    return NULL;
  }

  s24 = &kh_val(pl->s24_hash, k);
  // END

  return s24;
}

trinarkular_slash24_state_t *trinarkular_slash24_state_create(int metrics_cnt)
{
  trinarkular_slash24_state_t *state = NULL;

  // to save memory this is an 8bit field
  assert(metrics_cnt <= UINT8_MAX);

  if ((state = malloc_zero(sizeof(trinarkular_slash24_state_t))) == NULL) {
    return NULL;
  }

  // init per-/24 metrics
  // allocate enough metrics structures
  if ((state->metrics = malloc_zero(sizeof(trinarkular_slash24_metrics_t) *
                                    metrics_cnt * TRINARKULAR_SIGNAL_CNT)) ==
      NULL) {
    goto err;
  }

  state->metrics_cnt = metrics_cnt;

  return state;

err:
  trinarkular_slash24_state_destroy(state);
  return NULL;
}

void trinarkular_slash24_state_destroy(trinarkular_slash24_state_t *state)
{
  if (state == NULL) {
    return;
  }

  free_state(state);

  free(state);
}

int trinarkular_probelist_save_slash24_state(trinarkular_probelist_t *pl,
                                             trinarkular_slash24_t *s24,
                                             trinarkular_slash24_state_t *state)
{
  khiter_t k;
  int khret;
  trinarkular_slash24_state_t *dest;

  // FILE SPECIFIC IMPLEMENTATION
  k = kh_put(32state, pl->state_hash, s24->network_ip, &khret);
  if (khret == -1) {
    trinarkular_log("ERROR: Could not save /24 state");
    return -1;
  }

  dest = &kh_val(pl->state_hash, k);

  if (khret != 0) {
    // first use: need to clear the structure
    dest->metrics = NULL;
    dest->metrics_cnt = 0;
  }

  return copy_state(dest, state);
}

void *trinarkular_probelist_get_first_slash24_state(
        trinarkular_probelist_t *pl, khiter_t *iter) {

  if (pl == NULL || pl->state_hash == NULL) {
    return NULL;
  }

  *iter = kh_begin(pl->state_hash);
  while (*iter != kh_end(pl->state_hash)) {
    if (kh_exist(pl->state_hash, *iter)) {
      return &kh_val(pl->state_hash, *iter);
    }
    (*iter)++;
  }
  return NULL;
}

void *trinarkular_probelist_get_next_slash24_state(
        trinarkular_probelist_t *pl, khiter_t *iter) {

  void *ret = NULL;
  if (pl == NULL || pl->state_hash == NULL) {
    return NULL;
  }

  while (*iter != kh_end(pl->state_hash)) {
    if (kh_exist(pl->state_hash, *iter)) {
      ret = &kh_val(pl->state_hash, *iter);
    } else {
      ret = NULL;
    }
    (*iter)++;
    if (ret) {
      return ret;
    }
  }
  return NULL;
}

void *trinarkular_probelist_get_slash24_state(trinarkular_probelist_t *pl,
                                              trinarkular_slash24_t *s24)
{
  khiter_t k;

  // FILE SPECIFIC IMPLEMENTATION
  if ((k = kh_get(32state, pl->state_hash, s24->network_ip)) ==
      kh_end(pl->state_hash)) {
    return NULL;
  }

  return &kh_val(pl->state_hash, k);
}

uint32_t trinarkular_probelist_get_next_host(trinarkular_slash24_t *s24,
                                             trinarkular_slash24_state_t *state,
                                             int proto, uint16_t *port)
{
  trinarkular_slash24_hosts_t *h = &s24->proto[proto];
  trinarkular_signal_state_t *sig = &state->sig[proto];
  uint8_t idx;

  assert(h->hosts_cnt > 0);

  // current_host is an 8bit field, so this check will never actively reset the
  // counter when hosts_cnt is 256 -- we trust that the value will correctly
  // wrap to zero when it is post-incremented from 255
  if (sig->current_host >= h->hosts_cnt) {
    sig->current_host = 0;
  }

  idx = sig->current_host++;
  *port = (h->ports != NULL) ? h->ports[idx] : 0;
  return s24->network_ip | h->hosts[idx];
}
