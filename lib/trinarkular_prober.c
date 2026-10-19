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

#include "trinarkular_prober.h"
#include "trinarkular_driver_interface.h"
#include "trinarkular.h"
#include "trinarkular_driver.h"
#include "trinarkular_log.h"
#include "trinarkular_probelist.h"
#include "trinarkular_signal.h"
#include "config.h"
#include "khash.h"
#include "utils.h"
#include <arpa/inet.h>
#include <assert.h>
#include <czmq.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>
#include <wandio.h>

/** Print debugging info about adaptive/recovery probes */
/* #define DEBUG_PROBING */

/** To be run within a zloop handler */
#define CHECK_SHUTDOWN                                                         \
  do {                                                                         \
    if (zctx_interrupted != 0 || prober->shutdown != 0) {                      \
      trinarkular_log("Interrupted, shutting down");                           \
      return -1;                                                               \
    }                                                                          \
  } while (0)

// global metric prefix
#define METRIC_PREFIX "active.ping-slash24"

// metric prefix for per-/24 info
#define METRIC_PREFIX_SLASH24 METRIC_PREFIX ""

// metric prefix for prober metadata
#define METRIC_PREFIX_PROBER METRIC_PREFIX ".probers"

/** Metric prefix per signal (indexed by trinarkular_signal_id_t). ICMP keeps
 * the original prefix, so a single-protocol probelist produces exactly the
 * metrics it always has. The combined prefix names its contents so that adding
 * a protocol later cannot silently change what an existing series means. */
static const char *signal_prefixes[] = {
  METRIC_PREFIX,                      // TRINARKULAR_SIGNAL_ICMP
  "active.tcp-slash24",               // TRINARKULAR_SIGNAL_TCP
  "active.combined-icmp-tcp-slash24", // TRINARKULAR_SIGNAL_COMBINED
};

/** Names of probe protocols, for logging */
static const char *proto_names[] = {
  "icmp", // TRINARKULAR_PROBE_PROTO_ICMP
  "tcp",  // TRINARKULAR_PROBE_PROTO_TCP
};

#define CH_SLASH24 "__PFX_%s_24"

// used to coordinate between main thread and probelist reload thread
#define PROBELIST_RELOAD_NONE      0
#define PROBELIST_RELOAD_SCHEDULED 1
#define PROBELIST_RELOAD_RUNNING   2
#define PROBELIST_RELOAD_DONE      3

// the number of probelist states we have (ACTIVE and NEXT)
#define PROBELIST_STATES_CNT 2

/** Possible probe types */
enum {
  UNPROBED = 0,
  PERIODIC = 1,
  ADAPTIVE = 2,
  RECOVERY = 3,
  PROBE_TYPE_CNT = 4
};

static char *probe_types[] = {
  "unprobed", // 0 => UNPROBED
  "periodic", // 1 => PERIODIC
  "adaptive", // 2 => ADAPTIVE
  "recovery", // 3 => RECOVERY
};

/** Possible bayesian inference states for a /24 */
enum { UNCERTAIN = 0, DOWN = 1, UP = 2, BELIEF_STATE_CNT = 3 };

static char *belief_states[] = {
  "uncertain", // 0 => UNCERTAIN
  "down",      // 1 => DOWN
  "up",        // 2 => UP
};

#ifdef DEBUG_PROBING
static char *belief_icons[] = {
  "?", // 0 => UNCERTAIN
  "✘", // 1 => DOWN
  "✔", // 2 => UP
};
#endif

/** The number of recovery probes that may be sent for various A(E(b)) values.
 * To use this table, scale A(E(b)) by 100, and then cast to int and use the
 * result as an index.
 * E.g. A(E(b)) = 0.4325 => 43.25 => 43 => recovery_probe_cnt[43] = XX
 *
 * Array was generated using:
 * perl -e 'use POSIX ceil; foreach $i (1..99) { $x =
 * ceil(log(0.2)/log(1-$i/100)); $x=-1 if ($i < 10); print "$x, "; }'
 */
static int recovery_probe_cnt[] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, 16, 14, 13, 12, 11, 10, 10, 9, 9, 8, 8,
  7,  7,  7,  6,  6,  6,  6,  5,  5,  5,  5,  5,  5,  4,  4,  4,  4, 4, 4, 4,
  4,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  2,  2, 2, 2, 2,
  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2, 2, 2, 1,
  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1, 1, 1,
};

// recovery_probe_cnt has entries for A(E(b)) of 0.00-0.98; clamp so that
// 0.99 and 1.0 use the last entry rather than reading past the array
#define RECOVERY_PROBE_CNT_LEN                                                 \
  ((int)(sizeof(recovery_probe_cnt) / sizeof(recovery_probe_cnt[0])))
#define AEB_TO_RECOVERY(aeb)                                                   \
  recovery_probe_cnt[((int)((aeb)*100) < RECOVERY_PROBE_CNT_LEN)              \
                       ? (int)((aeb)*100)                                      \
                       : RECOVERY_PROBE_CNT_LEN - 1]

/** Stop exponential backoff once rounds_since_up reaches 16 */
#define RECOVERY_BACKOFF_MAX 16

#define RECOVERY_ELIGIBLE(state)                                               \
  ((state)->rounds_since_up <= 4 || (state)->rounds_since_up == 8 ||           \
   (state)->rounds_since_up % 16 == 0)

// set of ids that correspond to metrics in the kp
struct metrics {

  /** Value is the current round ID */
  int round_id;

  /** Value is NOW - round_start */
  int round_duration;

  /** Value is the number of /24s probed in the round (per protocol) */
  int round_probe_cnt[TRINARKULAR_PROBE_PROTO_CNT][PROBE_TYPE_CNT];

  /** Value is the number of /24s that we got responses for in the round */
  int round_probe_complete_cnt[TRINARKULAR_PROBE_PROTO_CNT][PROBE_TYPE_CNT];

  /** Value is the number of /24s that appeared alive this round */
  int round_responsive_cnt[TRINARKULAR_PROBE_PROTO_CNT][PROBE_TYPE_CNT];

  /** Values are the number of /24s in each state (per signal) */
  int slash24_state_cnts[TRINARKULAR_SIGNAL_CNT][BELIEF_STATE_CNT];

  /** Value is the number of /24s that we are probing (per signal) */
  int slash24_cnt[TRINARKULAR_SIGNAL_CNT];
};

/** Max number of rounds that are currently being tracked. Most of the time this
    will just be 2 */
#define MAX_IN_PROGRESS_ROUNDS 100

typedef struct probing_stats {

  /** The walltime that the round started at */
  uint64_t start_time;

  /** The number of probes sent this round (per protocol and type) */
  uint32_t probe_cnt[TRINARKULAR_PROBE_PROTO_CNT][PROBE_TYPE_CNT];

  /** The number of responses received this round */
  uint32_t probe_complete_cnt[TRINARKULAR_PROBE_PROTO_CNT][PROBE_TYPE_CNT];

  /** The number of responsive probes this round */
  uint32_t responsive_cnt[TRINARKULAR_PROBE_PROTO_CNT][PROBE_TYPE_CNT];

  /** The number of /24s in each state (per signal) */
  uint32_t slash24_state_cnts[TRINARKULAR_SIGNAL_CNT][BELIEF_STATE_CNT];

  /** The number of /24s that we are probing (per signal) */
  uint32_t slash24_cnt[TRINARKULAR_SIGNAL_CNT];

} probing_stats_t;

struct driver_wrap {
  int id;
  trinarkular_driver_t *driver;
  trinarkular_prober_t *prober;
};

struct params {

  /** Defaults to TRINARKULAR_PERIODIC_ROUND_DURATION_DEFAULT */
  uint64_t periodic_round_duration;

  /** Defaults to TRINARKULAR_PERIODIC_ROUND_SLICES_DEFAULT */
  int periodic_round_slices;

  /** Defaults to -1, unlimited */
  int periodic_round_limit;

  /** Defaults to 3 */
  uint16_t periodic_probe_timeout;

  /** Defaults to 1 (sleep for alignment) */
  int sleep_align_start;

  char *geoasn_csv_file;
};

#define PARAM(pname) (prober->params.pname)
#define ACTIVE_STAT(sname)                                                     \
  (prober->pl_states[prober->pl_state_active_idx].stats.sname)
#define NEXT_STAT(sname)                                                       \
  (prober->pl_states[!prober->pl_state_active_idx].stats.sname)

/** How often do we expect packet loss?
    (Taken from the paper) */
#define PACKET_LOSS_FREQUENCY 0.01

#define BELIEF_UP_FRAC 0.9
#define BELIEF_DOWN_FRAC 0.1
#define BELIEF_STATE(s)                                                        \
  (((s) < BELIEF_DOWN_FRAC) ? DOWN : ((s) > BELIEF_UP_FRAC) ? UP : UNCERTAIN)

// convenience macros to ease data structure access
#define ACTIVE_PL_STATE(p)   (p->pl_states[p->pl_state_active_idx])
#define ACTIVE_PL(p)         (p->pl_states[p->pl_state_active_idx].pl)
#define ACTIVE_KP_AGGR(p)    (p->pl_states[p->pl_state_active_idx].kp_aggr)
#define ACTIVE_KP_SLASH24(p) (p->pl_states[p->pl_state_active_idx].kp_slash24)
#define ACTIVE_METRICS(p)    (p->pl_states[p->pl_state_active_idx].metrics)
#define ACTIVE_SIGNALS(p)    (p->pl_states[p->pl_state_active_idx].signals)
#define NEXT_SIGNALS(p)      (p->pl_states[!p->pl_state_active_idx].signals)
#define HAS_SIGNAL(signals, sig) (((signals)&TRINARKULAR_SIGNAL_BIT(sig)) != 0)
#define NEXT_PL_STATE(p)     (p->pl_states[!p->pl_state_active_idx])
#define NEXT_PL(p)           (p->pl_states[!p->pl_state_active_idx].pl)
#define NEXT_KP_AGGR(p)      (p->pl_states[!p->pl_state_active_idx].kp_aggr)
#define NEXT_KP_SLASH24(p)   (p->pl_states[!p->pl_state_active_idx].kp_slash24)

/* Structure representing a probelist state.  We maintain two of these to
 * facilitate probelist reloads.
 */
typedef struct probelist_state {

  /** Probelist */
  trinarkular_probelist_t *pl;

  /** Key package (Per-/24 data) */
  timeseries_kp_t *kp_slash24;

  /** Key package (non-/24 data) */
  timeseries_kp_t *kp_aggr;

  /** Indexes into the KP for overall metrics */
  struct metrics metrics;

  /** Probing statistics */
  probing_stats_t stats;

  /** Signals the probelist provides (TRINARKULAR_SIGNAL_BIT mask) */
  uint8_t signals;
} probelist_state_t;

/* Structure representing a prober instance */
struct trinarkular_prober {

  /** Prober name */
  char *name;

  /** Prober name (timeseries safe) */
  char *name_ts;

  /** Configuration parameters */
  struct params params;

  /** Libtimeseries instance (Per-/24 data) */
  timeseries_t *ts_slash24;

  /** Libtimeseries instance (non-/24 data) */
  timeseries_t *ts_aggr;

  /** Has this prober been started? */
  int started;

  /** Should the prober shut down? */
  int shutdown;

  /** Two probelist states hold probelists and corresponding key packages */
  probelist_state_t pl_states[PROBELIST_STATES_CNT];

  /** Holds index of active probelist state. Either 0 or 1 */
  int pl_state_active_idx;

  /** zloop reactor instance */
  zloop_t *loop;

  /** Periodic probe timer ID */
  int periodic_timer_id;

  /** Probe Driver instances */
  struct driver_wrap drivers[TRINARKULAR_PROBER_DRIVER_MAX_CNT];

  /** Number of prober drivers in use */
  int drivers_cnt;

  /** Index of the next driver to use for probing */
  int drivers_next;

  /** Number of probes queued with the driver(s) */
  uint64_t outstanding_probe_cnt;

  /* ==== Periodic Probing State ==== */

  /** The number of /24s that are in a slice */
  int slice_size;

  /** The current slice (i.e. how many times the slice timer has fired) */
  uint64_t current_slice;

  /** Has probing started yet? */
  int probing_started;

  /** Do we have to reload the probelist? */
  int reload_probelist;

  /** Used by threads to coordinate probelist reload */
  sig_atomic_t reload_probelist_state;

  /** Filename of probelist */
  char *probelist_filename;

};

static char *graphite_safe(char *p)
{
  if (p == NULL) {
    return p;
  }

  char *r = p;
  while (*p != '\0') {
    if (*p == '.') {
      *p = '-';
    }
    if (*p == '*') {
      *p = '-';
    }
    p++;
  }
  return r;
}

#define BUFFER_LEN 1024

static int init_kp(trinarkular_prober_t *prober)
{
  char buf[BUFFER_LEN];
  int i, sig, proto;
  struct metrics *m = &NEXT_PL_STATE(prober).metrics;

  // create key packages
  if ((NEXT_KP_SLASH24(prober) =
       timeseries_kp_init(prober->ts_slash24, 0)) == NULL ||
      (NEXT_KP_AGGR(prober) = timeseries_kp_init(prober->ts_aggr, 0)) == NULL) {
    return -1;
  }

  // round id
  snprintf(buf, BUFFER_LEN, METRIC_PREFIX_PROBER ".%s.meta.round_id",
           prober->name_ts);
  if ((m->round_id = timeseries_kp_add_key(NEXT_KP_AGGR(prober), buf)) == -1) {
    return -1;
  }

  // round duration
  snprintf(buf, BUFFER_LEN, METRIC_PREFIX_PROBER ".%s.meta.round_duration",
           prober->name_ts);
  if ((m->round_duration = timeseries_kp_add_key(NEXT_KP_AGGR(prober), buf)) ==
      -1) {
    return -1;
  }

  for (sig = 0; sig < TRINARKULAR_SIGNAL_CNT; sig++) {
    proto = sig; // probe protocols share their signal's index
    if (!HAS_SIGNAL(NEXT_SIGNALS(prober), sig)) {
      for (i = 0; i < BELIEF_STATE_CNT; i++) {
        m->slash24_state_cnts[sig][i] = -1;
      }
      m->slash24_cnt[sig] = -1;
      if (proto < TRINARKULAR_PROBE_PROTO_CNT) {
        for (i = 0; i < PROBE_TYPE_CNT; i++) {
          m->round_probe_cnt[proto][i] = -1;
          m->round_probe_complete_cnt[proto][i] = -1;
          m->round_responsive_cnt[proto][i] = -1;
        }
      }
      continue;
    }

    // probe counts, for signals that send probes
    for (i = PERIODIC; proto < TRINARKULAR_PROBE_PROTO_CNT && i <= RECOVERY;
         i++) {
      // probe cnt
      snprintf(buf, BUFFER_LEN, "%s.probers.%s.probing.%s.probe_cnt",
               signal_prefixes[sig], prober->name_ts, probe_types[i]);
      if ((m->round_probe_cnt[proto][i] =
             timeseries_kp_add_key(NEXT_KP_AGGR(prober), buf)) == -1) {
        return -1;
      }

      // probe complete cnt
      snprintf(buf, BUFFER_LEN, "%s.probers.%s.probing.%s.completed_probe_cnt",
               signal_prefixes[sig], prober->name_ts, probe_types[i]);
      if ((m->round_probe_complete_cnt[proto][i] =
             timeseries_kp_add_key(NEXT_KP_AGGR(prober), buf)) == -1) {
        return -1;
      }

      // responsive cnt
      snprintf(buf, BUFFER_LEN, "%s.probers.%s.probing.%s.responsive_probe_cnt",
               signal_prefixes[sig], prober->name_ts, probe_types[i]);
      if ((m->round_responsive_cnt[proto][i] =
             timeseries_kp_add_key(NEXT_KP_AGGR(prober), buf)) == -1) {
        return -1;
      }
    }

    for (i = UNCERTAIN; i < BELIEF_STATE_CNT; i++) {
      snprintf(buf, BUFFER_LEN, "%s.probers.%s.states.%s_slash24_cnt",
               signal_prefixes[sig], prober->name_ts, belief_states[i]);
      if ((m->slash24_state_cnts[sig][i] =
             timeseries_kp_add_key(NEXT_KP_AGGR(prober), buf)) == -1) {
        return -1;
      }
    }

    snprintf(buf, BUFFER_LEN, "%s.probers.%s.slash24_cnt", signal_prefixes[sig],
             prober->name_ts);
    if ((m->slash24_cnt[sig] = timeseries_kp_add_key(NEXT_KP_AGGR(prober),
                                                     buf)) == -1) {
      return -1;
    }
  }

  return 0;
}

static void set_default_params(struct params *params)
{
  // round duration (10 bin)
  params->periodic_round_duration =
    TRINARKULAR_PROBER_PERIODIC_ROUND_DURATION_DEFAULT;

  // slices (60, i.e. every 10s)
  params->periodic_round_slices =
    TRINARKULAR_PROBER_PERIODIC_ROUND_SLICES_DEFAULT;

  // round limit (unlimited)
  params->periodic_round_limit = -1;

  // probe timeout
  params->periodic_probe_timeout =
    TRINARKULAR_PROBER_PERIODIC_PROBE_TIMEOUT_DEFAULT;

  // sleep to align
  params->sleep_align_start = 1;

  // file containing whitelisted geoasn pairs
  params->geoasn_csv_file = NULL;
}

static int slash24_latloss_metrics_create(trinarkular_prober_t *prober,
        trinarkular_slash24_state_t *s24_state,
        uint32_t slash24_ip) {

  char buf[BUFFER_LEN];

  snprintf(buf, BUFFER_LEN, METRIC_PREFIX_SLASH24
          ".single_s24.probers.%s.__S24_%u.latency",
          prober->name_ts, slash24_ip);
  if ((s24_state->latency_kp_index =
          timeseries_kp_add_key(NEXT_KP_SLASH24(prober), buf)) == -1) {
      return -1;
  }

  snprintf(buf, BUFFER_LEN, METRIC_PREFIX_SLASH24
          ".single_s24.probers.%s.__S24_%u.lostprobes",
          prober->name_ts, slash24_ip);
  if ((s24_state->loss_kp_index =
          timeseries_kp_add_key(NEXT_KP_SLASH24(prober), buf)) == -1) {
      return -1;
  }

  snprintf(buf, BUFFER_LEN, METRIC_PREFIX_SLASH24
          ".single_s24.probers.%s.__S24_%u.probessent",
          prober->name_ts, slash24_ip);
  if ((s24_state->probes_kp_index =
          timeseries_kp_add_key(NEXT_KP_SLASH24(prober), buf)) == -1) {
      return -1;
  }
  return 0;
}


static int slash24_metrics_create(trinarkular_prober_t *prober,
                                  trinarkular_slash24_metrics_t *metrics,
                                  const char *prefix,
                                  const char *slash24_string, const char *md,
                                  int per_block_stats)
{
  char buf[BUFFER_LEN];
  int i;
  uint64_t tmp;

  // only include per-block stats if this MD is a leaf (e.g., don't track blocks
  // at continent level)
  if (per_block_stats != 0) {
    // belief
    snprintf(buf, BUFFER_LEN, "%s.%s.probers.%s.blocks." CH_SLASH24 ".belief",
             prefix, md, prober->name_ts, slash24_string);
    if ((metrics->belief =
         timeseries_kp_add_key(NEXT_KP_SLASH24(prober), buf)) == -1) {
      return -1;
    }

    // state
    snprintf(buf, BUFFER_LEN, "%s.%s.probers.%s.blocks." CH_SLASH24 ".state",
             prefix, md, prober->name_ts, slash24_string);
    if ((metrics->state =
         timeseries_kp_add_key(NEXT_KP_SLASH24(prober), buf)) == -1) {
      return -1;
    }
  } else {
    metrics->belief = -1;
    metrics->state = -1;
  }

  // overall per-state stats
  for (i = UNCERTAIN; i < BELIEF_STATE_CNT; i++) {
    snprintf(buf, BUFFER_LEN, "%s.%s.probers.%s.%s_slash24_cnt", prefix, md,
             prober->name_ts, belief_states[i]);
    if ((metrics->overall[i] =
           timeseries_kp_get_key(NEXT_KP_AGGR(prober), buf)) == -1 &&
        (metrics->overall[i] =
           timeseries_kp_add_key(NEXT_KP_AGGR(prober), buf)) == -1) {
      return -1;
    }
  }

  // add this /24 to the UP state
  tmp = timeseries_kp_get(NEXT_KP_AGGR(prober), metrics->overall[UP]);
  timeseries_kp_set(NEXT_KP_AGGR(prober), metrics->overall[UP], tmp + 1);

  return 0;
}

/** Mark a set of /24 metrics as unused (signal not tracked for this /24) */
static void slash24_metrics_disable(trinarkular_slash24_metrics_t *metrics)
{
  int i;

  metrics->belief = -1;
  metrics->state = -1;
  for (i = 0; i < BELIEF_STATE_CNT; i++) {
    metrics->overall[i] = -1;
  }
}

/** Does the given signal apply to this /24? A probe protocol applies if the
 * /24 has hosts for it; the combined signal applies to every /24 of a
 * probelist that provides it. */
static int signal_applies(trinarkular_slash24_t *s24, uint8_t signals, int sig)
{
  if (!HAS_SIGNAL(signals, sig)) {
    return 0;
  }
  if (sig < TRINARKULAR_PROBE_PROTO_CNT) {
    return s24->proto[sig].hosts_cnt > 0;
  }
  return 1;
}

static trinarkular_slash24_state_t *
slash24_state_create(trinarkular_prober_t *prober, trinarkular_slash24_t *s24)
{
  trinarkular_slash24_state_t *state = NULL;
  trinarkular_signal_state_t *sig_state;
  trinarkular_slash24_metrics_t *metrics;
  uint32_t slash24_ip;
  char slash24_str[INET_ADDRSTRLEN];
  int i, sig;

  // need to first create the state
  if ((state = trinarkular_slash24_state_create(s24->md_cnt)) == NULL) {
    trinarkular_log("ERROR: Could not create slash24 state");
    return NULL;
  }

  // convert the /24 to a string
  slash24_ip = htonl(s24->network_ip);
  inet_ntop(AF_INET, &slash24_ip, slash24_str, INET_ADDRSTRLEN);
  graphite_safe(slash24_str);
  if (slash24_latloss_metrics_create(prober, state, s24->network_ip) != 0) {
      trinarkular_log("ERROR: Could not create slash24 latency/loss metrics for %s", slash24_str);
      return NULL;
  }

  for (sig = 0; sig < TRINARKULAR_SIGNAL_CNT; sig++) {
    sig_state = &state->sig[sig];
    metrics = &state->metrics[sig * s24->md_cnt];

    if (!signal_applies(s24, NEXT_SIGNALS(prober), sig)) {
      for (i = 0; i < s24->md_cnt; i++) {
        slash24_metrics_disable(&metrics[i]);
      }
      continue;
    }

    // initialize things
    sig_state->last_probe_type = UNPROBED;
    if (sig < TRINARKULAR_PROBE_PROTO_CNT) {
      ADAPTIVE_BUDGET_SET(sig_state, TRINARKULAR_PROBER_ROUND_PROBE_BUDGET);
      RECOVERY_BUDGET_SET(sig_state, AEB_TO_RECOVERY(s24->proto[sig].aeb));
    }
    sig_state->current_belief = 0.99; // as per paper
    sig_state->current_state = BELIEF_STATE(sig_state->current_belief);
    sig_state->rounds_since_up = 0;

    for (i = 0; i < s24->md_cnt; i++) {
      // create metrics for this metadata
      if (slash24_metrics_create(prober, &metrics[i], signal_prefixes[sig],
                                 slash24_str,
                                 s24->md[i]+2, // skip the '[LN]:' prefix
                                 (s24->md[i][0] == 'L') ? 1 : 0) != 0) {
        trinarkular_log("ERROR: Could not create slash24 metrics for %s",
                        s24->md[i]);
        return NULL;
      }
    }

    NEXT_STAT(slash24_state_cnts[sig][UP])++;
    NEXT_STAT(slash24_cnt[sig])++;
  }

  // to save a little memory, we free the metadata strings
  for (i = 0; i < s24->md_cnt; i++) {
    free(s24->md[i]);
  }
  free(s24->md);
  s24->md = NULL;
  s24->md_cnt = 0;

  // now, attach it
  if (trinarkular_probelist_save_slash24_state(NEXT_PL(prober),
                                               s24, state) != 0) {
    goto err;
  }

  // and destroy it
  trinarkular_slash24_state_destroy(state);

  return state;

err:
  trinarkular_slash24_state_destroy(state);
  return NULL;
}

static void reset_round_stats(trinarkular_prober_t *prober, uint64_t start_time)
{

  ACTIVE_STAT(start_time) = start_time;

  memset(ACTIVE_STAT(probe_cnt), 0, sizeof(ACTIVE_STAT(probe_cnt)));
  memset(ACTIVE_STAT(probe_complete_cnt), 0,
         sizeof(ACTIVE_STAT(probe_complete_cnt)));
  memset(ACTIVE_STAT(responsive_cnt), 0, sizeof(ACTIVE_STAT(responsive_cnt)));
}

/** Queue a probe for the given /24 with the given protocol */
static int queue_slash24_probe(trinarkular_prober_t *prober,
                               trinarkular_slash24_t *s24,
                               trinarkular_slash24_state_t *state, int proto,
                               int probe_type)
{
  uint32_t host_ip;
  uint16_t port;
  trinarkular_signal_state_t *sig_state = &state->sig[proto];

  trinarkular_probe_req_t req = {
    0, PARAM(periodic_probe_timeout), proto, 0,
  };
  struct driver_wrap *dw;

  int ret;

  assert(state != NULL);
  assert(proto < TRINARKULAR_PROBE_PROTO_CNT);
  // slash24_state is valid here

  // identify the appropriate host to probe
  host_ip = trinarkular_probelist_get_next_host(s24, state, proto, &port);
  req.target_ip = htonl(host_ip);
  req.port = port;

  // indicate that we are waiting for a response
  sig_state->last_probe_type = probe_type;
  ACTIVE_STAT(probe_cnt[proto][probe_type])++;

  // decrement the probe budget (periodic doesn't affect this)
  // (its up to the caller to ensure that we have enough probes in the budget)
  if (probe_type == ADAPTIVE) {
    assert(ADAPTIVE_BUDGET(sig_state) > 0);
    ADAPTIVE_BUDGET_SET(sig_state, ADAPTIVE_BUDGET(sig_state) - 1);
  } else if (probe_type == RECOVERY) {
    assert(RECOVERY_BUDGET(sig_state) > 0);
    RECOVERY_BUDGET_SET(sig_state, RECOVERY_BUDGET(sig_state) - 1);
  }

  dw = &prober->drivers[prober->drivers_next];
  if ((ret = trinarkular_driver_queue_req(dw->driver, &req)) != 0) {
    return -1;
  }
  prober->outstanding_probe_cnt++;

  // move on to the next driver ready for the next probe
  prober->drivers_next = (prober->drivers_next + 1) % prober->drivers_cnt;

  // save the state
  if (trinarkular_probelist_save_slash24_state(ACTIVE_PL(prober),
                                               s24, state) != 0) {
    return -1;
  }

  return 0;
}

static void set_slash24_kp_values(trinarkular_prober_t *prober) {
  khiter_t k;
  trinarkular_slash24_state_t *state;
  trinarkular_probelist_t *pl;

  pl = ACTIVE_PL(prober);
  if (!pl) {
      return;
  }

  state = trinarkular_probelist_get_first_slash24_state(pl, &k);
  while (state != NULL) {
    if (state->replies_seen <= state->probes_sent) {
      timeseries_kp_set(ACTIVE_KP_SLASH24(prober),
              state->loss_kp_index,
              state->probes_sent - state->replies_seen);
    }
    timeseries_kp_set(ACTIVE_KP_SLASH24(prober),
        state->probes_kp_index, state->probes_sent);

    if (state->probes_sent > 0) {
      timeseries_kp_set(ACTIVE_KP_SLASH24(prober),
          state->latency_kp_index,
          (uint32_t)(state->cumulative_rtt / state->probes_sent));
    }
    state = trinarkular_probelist_get_next_slash24_state(pl, &k);
  }
}

static int end_of_round(trinarkular_prober_t *prober, int round_id)
{
  uint64_t now = zclock_time();
  uint64_t aligned_start =
    ((uint64_t)(ACTIVE_STAT(start_time) / PARAM(periodic_round_duration))) *
    PARAM(periodic_round_duration);
  int i, sig;
  struct metrics *m = &ACTIVE_METRICS(prober);

  set_slash24_kp_values(prober);

  timeseries_kp_set(ACTIVE_KP_AGGR(prober),
                    ACTIVE_METRICS(prober).round_id, round_id);
  timeseries_kp_set(ACTIVE_KP_AGGR(prober),
                    ACTIVE_METRICS(prober).round_duration,
                    now - ACTIVE_STAT(start_time));

  for (sig = 0; sig < TRINARKULAR_SIGNAL_CNT; sig++) {
    if (!HAS_SIGNAL(ACTIVE_SIGNALS(prober), sig)) {
      continue;
    }

    for (i = PERIODIC; sig < TRINARKULAR_PROBE_PROTO_CNT && i < PROBE_TYPE_CNT;
         i++) {
      timeseries_kp_set(ACTIVE_KP_AGGR(prober), m->round_probe_cnt[sig][i],
                        ACTIVE_STAT(probe_cnt[sig][i]));
      timeseries_kp_set(ACTIVE_KP_AGGR(prober),
                        m->round_probe_complete_cnt[sig][i],
                        ACTIVE_STAT(probe_complete_cnt[sig][i]));
      timeseries_kp_set(ACTIVE_KP_AGGR(prober), m->round_responsive_cnt[sig][i],
                        ACTIVE_STAT(responsive_cnt[sig][i]));
    }

    for (i = UNCERTAIN; i < BELIEF_STATE_CNT; i++) {
      timeseries_kp_set(ACTIVE_KP_AGGR(prober), m->slash24_state_cnts[sig][i],
                        ACTIVE_STAT(slash24_state_cnts[sig][i]));
    }

    timeseries_kp_set(ACTIVE_KP_AGGR(prober), m->slash24_cnt[sig],
                      ACTIVE_STAT(slash24_cnt[sig]));
  }

  trinarkular_log("round %d completed in %" PRIu64 "ms (ideal: %" PRIu64 "ms)",
                  round_id, now - ACTIVE_STAT(start_time),
                  PARAM(periodic_round_duration));
  for (sig = 0; sig < TRINARKULAR_PROBE_PROTO_CNT; sig++) {
    if (!HAS_SIGNAL(ACTIVE_SIGNALS(prober), sig)) {
      continue;
    }
    trinarkular_log("round periodic response rate (%s): %d/%d (%0.0f%%)",
                    proto_names[sig], ACTIVE_STAT(responsive_cnt[sig][PERIODIC]),
                    ACTIVE_STAT(probe_cnt[sig][PERIODIC]),
                    ACTIVE_STAT(responsive_cnt[sig][PERIODIC]) * 100.0 /
                      ACTIVE_STAT(probe_cnt[sig][PERIODIC]));
  }

  // flush the kps
  if (timeseries_kp_flush(ACTIVE_KP_AGGR(prober), aligned_start / 1000) != 0 ||
      timeseries_kp_flush(ACTIVE_KP_SLASH24(prober),
                          aligned_start / 1000) != 0) {
    return -1;
  }
  return 0;
}

int probelist_state_destroy(probelist_state_t *pl_state)
{
  trinarkular_probelist_destroy(pl_state->pl);
  pl_state->pl = NULL;

  // destroy the key packages
  timeseries_kp_free(&pl_state->kp_slash24);
  pl_state->kp_slash24 = NULL;
  timeseries_kp_free(&pl_state->kp_aggr);
  pl_state->kp_aggr = NULL;

  return 0;
}

static int process_geoasn_line(trinarkular_prober_t *prober, char *buffer) {
  char buf[BUFFER_LEN];
  int i, sig;
  char *tok, *ptr;
  uint64_t asn, regionid;

  // add a timeseries key for every entry in the whitelist
  tok = strtok(buffer, ",");
  if (tok == NULL) {
      return -1;
  }

  errno = 0;
  asn = strtoul(tok, NULL, 10);
  if (errno) {
    fprintf(stderr, "Invalid ASN field: %s\n", tok);
    return -1;
  }

  while ((tok = strtok(NULL, ",")) != NULL) {
    if (tok[0] >= '0' && tok[0] <= '9') {
      /* it is a region ID */
      errno = 0;
      regionid = strtoul(tok, NULL, 10);
      if (errno) {
        fprintf(stderr, "Invalid region ID: %s\n", tok);
        return -1;
      }

      for (sig = 0; sig < TRINARKULAR_SIGNAL_CNT; sig++) {
        if (!HAS_SIGNAL(NEXT_SIGNALS(prober), sig)) {
          continue;
        }
        for (i = UNCERTAIN; i < BELIEF_STATE_CNT; i++) {
          snprintf(buf, BUFFER_LEN,
                 "%s.geoasn.ipinfo.region.%lu.%lu.probers.%s.%s_slash24_cnt",
                 signal_prefixes[sig], asn, regionid, prober->name_ts,
                 belief_states[i]);
          if (timeseries_kp_get_key(NEXT_KP_AGGR(prober), buf) == -1 &&
                timeseries_kp_add_key(NEXT_KP_AGGR(prober), buf) == -1) {
            return -1;
          }
        }
      }
    } else {
      /* it is a country (hopefully) */
      if ((ptr = strchr(tok, '\n')) != NULL) {
          *ptr = '\0';
      }
      if (*tok == '\0') {
          break;
      }
      if (strlen(tok) != 2) {
          fprintf(stderr, "Invalid country code: %s\n", tok);
          return -1;
      }

      for (sig = 0; sig < TRINARKULAR_SIGNAL_CNT; sig++) {
        if (!HAS_SIGNAL(NEXT_SIGNALS(prober), sig)) {
          continue;
        }
        for (i = UNCERTAIN; i < BELIEF_STATE_CNT; i++) {
          snprintf(buf, BUFFER_LEN,
                 "%s.geoasn.ipinfo.country.%lu.%s.probers.%s.%s_slash24_cnt",
                 signal_prefixes[sig], asn, tok, prober->name_ts,
                 belief_states[i]);
          if (timeseries_kp_get_key(NEXT_KP_AGGR(prober), buf) == -1 &&
                timeseries_kp_add_key(NEXT_KP_AGGR(prober), buf) == -1) {
            return -1;
          }
        }
      }
    }
  }
  return 0;
}

static int process_geoasn_whitelist(trinarkular_prober_t *prober)
{
  io_t *file;
  char buffer[2048];
  int read, rc = 1;

  if (PARAM(geoasn_csv_file) == NULL) {
    return 0;
  }

  if ((file = wandio_create(PARAM(geoasn_csv_file))) == NULL) {
    fprintf(stderr, "ERROR: failed to open file '%s'\n",
            PARAM(geoasn_csv_file));
    return -1;
  }

  while ((read = wandio_fgets(file, &buffer, 2048, 0)) > 0) {
    if (strlen(buffer) == 0) {
        continue;
    }
    if (process_geoasn_line(prober, buffer) < 0) {
      fprintf(stderr, "Malformed line in region csv file: %s \n", buffer);
      rc = -1;
      break;
    }
  }
  wandio_destroy(file);
  return rc;
}

static int trinarkular_prober_prepare_probelist(trinarkular_prober_t *prober)
{
  int i = 0;
  trinarkular_slash24_t *s24 = NULL;

  trinarkular_log("Preparing probelist to be assigned");

  assert(NEXT_PL(prober) == NULL);

  // create new probelist
  if ((NEXT_PL(prober) =
       trinarkular_probelist_create(prober->probelist_filename)) == NULL) {
    trinarkular_log("ERROR: Could not create probelist file");
    goto err;
  }

  NEXT_SIGNALS(prober) = trinarkular_probelist_get_signals(NEXT_PL(prober));
  for (i = 0; i < TRINARKULAR_SIGNAL_CNT; i++) {
    if (HAS_SIGNAL(NEXT_SIGNALS(prober), i)) {
      trinarkular_log("Probelist provides the %s signal", signal_prefixes[i]);
    }
  }

  // re-initialize key packages
  if (init_kp(prober) != 0) {
    trinarkular_log("ERROR: Could not create timeseries key package");
    goto err;
  }

  // re-initialize statistics
  memset(NEXT_PL_STATE(prober).stats.slash24_state_cnts, 0,
         sizeof(NEXT_PL_STATE(prober).stats.slash24_state_cnts));
  memset(NEXT_PL_STATE(prober).stats.slash24_cnt, 0,
         sizeof(NEXT_PL_STATE(prober).stats.slash24_cnt));

  // and create all the state (including timeseries metrics)
  trinarkular_probelist_reset_slash24_iter(NEXT_PL(prober));

  // create ts keys for all whitelisted metrics, so we will generate
  // suitable '0' results if the geoasn pair does not appear in our
  // probelist
  if (process_geoasn_whitelist(prober) < 0) {
    trinarkular_log("ERROR: Could not parse geoasn whitelist");
    goto err;
  }

  // iterates over the entire probelist.
  while ((s24 =
          trinarkular_probelist_get_next_slash24(NEXT_PL(prober))) != NULL) {
    if (slash24_state_create(prober, s24) == NULL) {
      trinarkular_log("ERROR: Could not create /24 state");
      goto err;
    }
  }

  // force libtimeseries to resolve all keys
  trinarkular_log("Resolving %d timeseries keys (Per-/24 KP)",
                  timeseries_kp_size(NEXT_KP_SLASH24(prober)));
  while (timeseries_kp_resolve(NEXT_KP_SLASH24(prober)) != 0) {
    trinarkular_log("WARN: Could not resolve timeseries keys. Retrying");
    if (sleep(10) != 0) {
      trinarkular_log("WARN: Sleep interrupted, exiting");
      return -1;
    }
  }
  trinarkular_log("Resolving %d timeseries keys (Aggregate KP)",
                  timeseries_kp_size(NEXT_KP_AGGR(prober)));
  while (timeseries_kp_resolve(NEXT_KP_AGGR(prober)) != 0) {
    trinarkular_log("WARN: Could not resolve timeseries keys. Retrying");
    if (sleep(10) != 0) {
      trinarkular_log("WARN: Sleep interrupted, exiting");
      return -1;
    }
  }

  return 0;

err:
  probelist_state_destroy(&NEXT_PL_STATE(prober));
  prober->reload_probelist_state = PROBELIST_RELOAD_NONE;
  return -1;
}

static void trinarkular_prober_update_probelist(trinarkular_prober_t *prober)
{
  trinarkular_log("Updating probelist");

  // destroy active state if there is any (there may not be if we are loading
  // the probelist for the first time)
  probelist_state_destroy(&ACTIVE_PL_STATE(prober));

  // make index point to the other probelist state now
  prober->pl_state_active_idx = !prober->pl_state_active_idx;

  // compute the slice size
  prober->slice_size = trinarkular_probelist_get_slash24_cnt(ACTIVE_PL(prober))/
                       PARAM(periodic_round_slices);
  if (prober->slice_size * PARAM(periodic_round_slices) <
      trinarkular_probelist_get_slash24_cnt(ACTIVE_PL(prober))) {
    // round up to ensure we cover everything in the interval
    prober->slice_size++;
  }
  trinarkular_log("Periodic Probing Slice Size: %d", prober->slice_size);

  trinarkular_log("Probelist size: %d /24s, version: %s",
                  trinarkular_probelist_get_slash24_cnt(ACTIVE_PL(prober)),
                  trinarkular_probelist_get_version(ACTIVE_PL(prober)));
}

static void *reload_probelist(void *arg)
{
  trinarkular_log("I'm the thread that reloads the probelist");

  trinarkular_prober_t *prober = (trinarkular_prober_t *) arg;

  if (trinarkular_prober_prepare_probelist(prober) != 0) {
    trinarkular_log("ERROR: trinarkular_prober_prepare_probelist() failed");
    return NULL;
  }

  prober->reload_probelist_state = PROBELIST_RELOAD_DONE;
  trinarkular_log("Probelist successfully reloaded in separate thread");

  return NULL;
}

static void schedule_probelist_reload(trinarkular_prober_t *prober)
{
  pthread_t handle = 0;
  int ret = 0;

  trinarkular_log("A probelist reload is scheduled");

  // run probelist reload code in separate thread so we don't stall probing
  trinarkular_log("Creating thread to reload probelist");
  if ((ret = pthread_create(&handle, NULL, reload_probelist,
                            (void *) prober)) == 0) {
    // detach thread, so its resources are automatically freed, without having
    // to call pthread_join()
    if ((ret = pthread_detach(handle)) != 0) {
      trinarkular_log("ERROR: pthread_detach() returned %d", ret);
    }
  } else {
    trinarkular_log("ERROR: pthread_create() returned %d", ret);
    prober->reload_probelist_state = PROBELIST_RELOAD_NONE;
    return;
  }
  prober->reload_probelist_state = PROBELIST_RELOAD_RUNNING;
}

/** Queue the next set of periodic probes */
static int handle_timer(zloop_t *loop, int timer_id, void *arg)
{
  trinarkular_prober_t *prober = (trinarkular_prober_t *)arg;
  int slice_cnt = 0;
  int queued_cnt = 0;

  uint64_t probing_round = prober->current_slice / PARAM(periodic_round_slices);

  uint64_t now = zclock_time();

  trinarkular_slash24_t *s24 = NULL;         // BORROWED
  trinarkular_slash24_state_t *state = NULL; // BORROWED
  trinarkular_signal_state_t *sig_state;     // BORROWED
  int proto;
  int probe_proto_cnt;

  CHECK_SHUTDOWN;

  // do we have to reload the probelist?
  if (prober->reload_probelist_state == PROBELIST_RELOAD_SCHEDULED) {
    schedule_probelist_reload(prober);
  }

  // have we reached the end of the probelist and need to start over?
  if (prober->probing_started == 0 ||
      trinarkular_probelist_has_more_slash24(ACTIVE_PL(prober)) == 0) {
    // only reset if the round has ended (should only happen when probelist is
    // smaller than slice count
    if (prober->current_slice % PARAM(periodic_round_slices) != 0) {
      trinarkular_log("No /24s left to probe in round %" PRIu64, probing_round);
      goto done;
    }

    // dump end of round stats
    if (probing_round > 0) {
      trinarkular_log("ending round %d", probing_round - 1);

      if (end_of_round(prober, probing_round - 1) != 0) {
        trinarkular_log("WARN: Could not dump end-of-round stats");
      }

      // check if we're done reloading the probelist
      if (prober->reload_probelist_state == PROBELIST_RELOAD_RUNNING) {
        trinarkular_log("Probelist reload still in progress.  "
                        "Waiting until next round.");
      } else if (prober->reload_probelist_state == PROBELIST_RELOAD_DONE) {
        trinarkular_log("Probelist reload done.  Now updating probelist.");
        trinarkular_prober_update_probelist(prober);
        prober->reload_probelist_state = PROBELIST_RELOAD_NONE;
      }
    }

    // check if we reached the round limit
    if (PARAM(periodic_round_limit) > 0 &&
        probing_round >= PARAM(periodic_round_limit)) {
      trinarkular_log("round limit (%d) reached, shutting down",
                      PARAM(periodic_round_limit));
      return -1;
    }

    trinarkular_log("starting round %d", probing_round);
    trinarkular_probelist_reset_slash24_iter(ACTIVE_PL(prober));

    // reset cumulative RTT and probe counters in every /24 state
    trinarkular_probelist_reset_slash24_counters(ACTIVE_PL(prober));

    // reset round stats
    reset_round_stats(prober, now);

    prober->probing_started = 1;
  }

  // check if there are still a few slices of probes outstanding.  this is a
  // good indication that scamper is not keeping up with the probing rate
  // (probably due to our timers firing close together).  in this case we skip
  // the entire slice. (each /24 gets a periodic probe per protocol, so the
  // limit scales with the number of protocols probed)
  probe_proto_cnt = 0;
  for (proto = 0; proto < TRINARKULAR_PROBE_PROTO_CNT; proto++) {
    probe_proto_cnt += HAS_SIGNAL(ACTIVE_SIGNALS(prober), proto) ? 1 : 0;
  }
  if (prober->outstanding_probe_cnt >
      prober->slice_size * 5 * probe_proto_cnt) {
    trinarkular_log(
      "WARN: %d outstanding requests (slice size is %d), skipping slice.",
      prober->outstanding_probe_cnt, prober->slice_size);
    goto done;
  }

  trinarkular_log("INFO: %" PRIu64 " outstanding requests (slice size is %d)",
                  prober->outstanding_probe_cnt, prober->slice_size);

  for (slice_cnt = 0; slice_cnt < prober->slice_size; slice_cnt++) {
    // get a slash24 to probe
    if ((s24 =
         trinarkular_probelist_get_next_slash24(ACTIVE_PL(prober))) == NULL) {
      // end of /24s
      break;
    }
    // get the state for this /24
    if ((state = trinarkular_probelist_get_slash24_state(ACTIVE_PL(prober),
                                                         s24)) == NULL) {
      return -1;
    }

    // one periodic probe per protocol this /24 has hosts for
    for (proto = 0; proto < TRINARKULAR_PROBE_PROTO_CNT; proto++) {
      if (!signal_applies(s24, ACTIVE_SIGNALS(prober), proto)) {
        continue;
      }
      sig_state = &state->sig[proto];

      // if we still haven't got a response to our last probe, lets give up on
      // it and send a new probe
      if (sig_state->last_probe_type != UNPROBED) {
        trinarkular_log("INFO: re-probing /24 (%s) with last_probe_type of %d",
                        proto_names[proto], sig_state->last_probe_type);
        sig_state->last_probe_type = UNPROBED;
      }

      // reset the probe budgets
      ADAPTIVE_BUDGET_SET(sig_state, TRINARKULAR_PROBER_ROUND_PROBE_BUDGET);
      RECOVERY_BUDGET_SET(sig_state, AEB_TO_RECOVERY(s24->proto[proto].aeb));
      if (BELIEF_STATE(sig_state->current_belief) == UP) {
        sig_state->rounds_since_up = 0;
      } else {
        if (sig_state->rounds_since_up < 255) {
          sig_state->rounds_since_up++;
        } else {
          sig_state->rounds_since_up = RECOVERY_BACKOFF_MAX;
        }
      }
      // queue a probe to a random host
      if (queue_slash24_probe(prober, s24, state, proto, PERIODIC) != 0) {
        return -1;
      }
      if (proto == TRINARKULAR_PROBE_PROTO_ICMP) {
        state->probes_sent ++;
      }
    }
    queued_cnt++;
  }

  trinarkular_log("Queued %d /24s in slice %" PRIu64 " (round: %" PRIu64 ")",
                  queued_cnt, prober->current_slice, probing_round);

done:
  prober->current_slice++;
  CHECK_SHUTDOWN;
  return 0;
}

// update the bayesian model given a positive (1) or negative (0) probe response
// to a probe whose protocol has response rate aeb (A(E(b)))
static float update_bayesian_belief(float aeb, float current_belief,
                                    int probe_response)
{
  // B(U)
  float BU = current_belief;

  // B(~U)
  float BD = 1.0 - BU;

  // P(p|~U)
  float PpD = (1.0 - PACKET_LOSS_FREQUENCY) / TRINARKULAR_SLASH24_HOST_CNT;

  // P(p|U)
  float PpU = aeb;

  // P(n|U)
  float PnU = 1.0 - PpU;

  // P(n|~U)
  float PnD = 1.0 - PpD;

  float new_belief_down;

  // Positive response
  if (probe_response != 0) {
    new_belief_down = (PpD * BD) / ((PpD*BD) + (PpU*BU));
  } else { // Negative, or no response
    new_belief_down = (PnD*BD) / ((PnD*BD) + (PnU*BU));
  }

  // capping as per sec 4.2 of paper
  if (new_belief_down > 0.99) {
    new_belief_down = 0.99;
  } else if (new_belief_down < 0.01) {
    new_belief_down = 0.01;
  }

  // convert B(~U) to B(U) and return
  return 1 - new_belief_down;
}

#define BECOMING_UNCERTAIN(old, new)                                           \
  ((BELIEF_STATE(new) == UNCERTAIN) ||                                         \
   (BELIEF_STATE(old) == UP && (old > new)) ||                                 \
   (BELIEF_STATE(old) == DOWN && (new > old)))

/** Record a signal's new stable state: per-/24 belief and state series, and
 * the per-state /24 counts */
static void update_signal_state(trinarkular_prober_t *prober,
                                trinarkular_slash24_state_t *state, int sig,
                                float new_belief_up)
{
  trinarkular_signal_state_t *sig_state = &state->sig[sig];
  trinarkular_slash24_metrics_t *metrics =
    &state->metrics[sig * state->metrics_cnt];
  uint64_t tmp;
  int key;
  int i;

  // update overall belief stats
  // decrement current state
  ACTIVE_STAT(slash24_state_cnts[sig][sig_state->current_state])--;
  // increment new state
  ACTIVE_STAT(slash24_state_cnts[sig][BELIEF_STATE(new_belief_up)])++;

  // update the timeseries
  for (i = 0; i < state->metrics_cnt; i++) {
    if (metrics[i].belief != -1) {
      timeseries_kp_set(ACTIVE_KP_SLASH24(prober), metrics[i].belief,
                        new_belief_up * 100);
    }
    if (metrics[i].state != -1) {
      timeseries_kp_set(ACTIVE_KP_SLASH24(prober), metrics[i].state,
                        BELIEF_STATE(new_belief_up));
    }

    // update the overall stats for this metric
    // decrement the old state
    key = metrics[i].overall[sig_state->current_state];
    tmp = timeseries_kp_get(ACTIVE_KP_AGGR(prober), key);
    assert(tmp > 0);
    timeseries_kp_set(ACTIVE_KP_AGGR(prober), key, tmp - 1);
    // increment the new state
    key = metrics[i].overall[BELIEF_STATE(new_belief_up)];
    tmp = timeseries_kp_get(ACTIVE_KP_AGGR(prober), key);
    timeseries_kp_set(ACTIVE_KP_AGGR(prober), key, tmp + 1);
  }

  // update the stable state
  sig_state->current_state = BELIEF_STATE(new_belief_up);
}

/** Feed a response into the combined signal (decision 1.2 (a1)): one belief,
 * updated by every protocol's responses, each using its own protocol's
 * A(E(b)) as P(response | up). The combined signal sends no probes of its own;
 * it settles once no protocol is still probing the /24. */
static void update_combined_signal(trinarkular_prober_t *prober,
                                   trinarkular_slash24_t *s24,
                                   trinarkular_slash24_state_t *state,
                                   int proto, int verdict)
{
  trinarkular_signal_state_t *comb = &state->sig[TRINARKULAR_SIGNAL_COMBINED];
  int p;

  if (!signal_applies(s24, ACTIVE_SIGNALS(prober),
                      TRINARKULAR_SIGNAL_COMBINED)) {
    return;
  }

  comb->current_belief = update_bayesian_belief(
    s24->proto[proto].aeb, comb->current_belief, verdict);

  for (p = 0; p < TRINARKULAR_PROBE_PROTO_CNT; p++) {
    if (state->sig[p].last_probe_type != UNPROBED) {
      return; // still converging
    }
  }

  update_signal_state(prober, state, TRINARKULAR_SIGNAL_COMBINED,
                      comb->current_belief);
}

static int handle_driver_resp(zloop_t *loop, zsock_t *reader, void *arg)
{
  struct driver_wrap *dw = (struct driver_wrap *)arg;
  trinarkular_prober_t *prober = dw->prober;
  trinarkular_probe_resp_t resp;
  trinarkular_slash24_t *s24 = NULL;
  trinarkular_slash24_state_t *state = NULL;
  trinarkular_signal_state_t *sig_state = NULL;
  float new_belief_up;
  int proto;

  CHECK_SHUTDOWN;

  if (trinarkular_driver_recv_resp(dw->driver, &resp, 0) != 1) {
    trinarkular_log("ERROR: Could not receive response");
    goto err;
  }

  // TARGET IP IS IN NETWORK BYTE ORDER

  // find the /24 for this probe
  if ((s24 = trinarkular_probelist_get_slash24(
         ACTIVE_PL(prober), (ntohl(resp.target_ip) &
                             TRINARKULAR_SLASH24_NETMASK))) == NULL) {
    trinarkular_log("WARN: Missing /24 for %x", ntohl(resp.target_ip));
    return 0;
  }
  prober->outstanding_probe_cnt--;

  // grab the state for this /24
  if ((state = trinarkular_probelist_get_slash24_state(ACTIVE_PL(prober),
                                                       s24)) == NULL) {
    trinarkular_log("ERROR: Missing state for %x", ntohl(resp.target_ip));
    goto err;
  }

  // the response says which protocol it answers, so ICMP and TCP probes
  // outstanding to the same /24 at once are attributed correctly
  proto = resp.proto;
  if (proto >= TRINARKULAR_PROBE_PROTO_CNT ||
      !signal_applies(s24, ACTIVE_SIGNALS(prober), proto)) {
    trinarkular_log("WARN: Response for %x with unexpected protocol %d",
                    ntohl(resp.target_ip), proto);
    return 0;
  }
  sig_state = &state->sig[proto];

  // since periodic probing will reset adaptive probing state, this can cause
  // responses to become out of sync. simply ignore a response that we don't
  // care about. (NB: in practice this should rarely, if ever, happen since a
  // round is much longer than the timeout)
  if (sig_state->last_probe_type == UNPROBED) {
    return 0;
  }

  // latency/loss series are ICMP only, as before protocols existed
  if (proto == TRINARKULAR_PROBE_PROTO_ICMP &&
      resp.verdict == TRINARKULAR_PROBE_RESPONSIVE) {
      state->replies_seen ++;
      state->cumulative_rtt += resp.rtt;
  }

  // update the overall per-round statistics
  ACTIVE_STAT(probe_complete_cnt[proto][sig_state->last_probe_type])++;
  ACTIVE_STAT(responsive_cnt[proto][sig_state->last_probe_type]) +=
    resp.verdict;

  new_belief_up = update_bayesian_belief(
    s24->proto[proto].aeb, sig_state->current_belief, resp.verdict);

#ifdef DEBUG_PROBING
  fprintf(stdout, "%s %f (%s) -> %f (%s)", proto_names[proto],
          sig_state->current_belief,
          belief_icons[BELIEF_STATE(sig_state->current_belief)], new_belief_up,
          belief_icons[BELIEF_STATE(new_belief_up)]);
#endif

  // if new state is uncertain, or we are moving toward uncertainty, send more
  // probes
  if (BECOMING_UNCERTAIN(sig_state->current_belief, new_belief_up)) {
    // we'd like to send an adaptive probe, but do we have any left in the
    // budget?
    if (ADAPTIVE_BUDGET(sig_state) > 0) {
      if (queue_slash24_probe(prober, s24, state, proto, ADAPTIVE) != 0) {
        return -1;
      }
#ifdef DEBUG_PROBING
      fprintf(stdout, " ADAPTIVE");
#endif

      // AK removes this urgent recovery to save some probes. consider enabling
      // if probe usage is not a problem as it might help some unstable blocks
#if 0
      // no more adaptive probes left, but if we are changing state away from
      // UP, we'd better be darn sure, so lets switch to recovery probing right
      // now (unless this is the first round...)
    } else if (sig_state->current_state == UP &&
               RECOVERY_BUDGET(sig_state) > 0 &&
               prober->current_slice != 0) {
      // queue a recovery probe
      if (queue_slash24_probe(prober, s24, state, proto, RECOVERY) != 0) {
        return -1;
      }
#ifdef DEBUG_PROBING
      fprintf(stdout, " ADAPTIVE-RECOVERY");
#endif
#endif

      // we ideally would have liked to send an adaptive probe since belief has
      // changed, but we're out of probes, so we give up and if the block is not
      // already uncertain, we move belief to 0.5 (uncertain)
    } else {
      if (BELIEF_STATE(new_belief_up) != UNCERTAIN) {
        new_belief_up = 0.5; // => UNCERTAIN
      }
      sig_state->last_probe_type = UNPROBED;
#ifdef DEBUG_PROBING
      fprintf(stdout, " DONE-ADAPTIVE");
#endif
    }

    // otherwise, if we are down and staying down, send recovery probes to try
    // and get back up.
  } else if (BELIEF_STATE(sig_state->current_belief) == DOWN &&
             BELIEF_STATE(new_belief_up) == DOWN &&
             RECOVERY_ELIGIBLE(sig_state) != 0 &&
             RECOVERY_BUDGET(sig_state) > 0) {
    // queue a recovery probe
    if (queue_slash24_probe(prober, s24, state, proto, RECOVERY) != 0) {
      return -1;
    }
#ifdef DEBUG_PROBING
    fprintf(stdout, " RECOVERY");
#endif

  } else {
    // No adaptive/recovery probe sent
    sig_state->last_probe_type = UNPROBED;
#ifdef DEBUG_PROBING
    fprintf(stdout, " DONE");
#endif
  }

#ifdef DEBUG_PROBING
  fprintf(stdout, " %d %d %d\n", ADAPTIVE_BUDGET(sig_state),
          RECOVERY_BUDGET(sig_state), sig_state->rounds_since_up);
#endif

  // only update statistics if we have stopped probing this /24 (otherwise we
  // run the risk of dumping info about a /24 while the prober is converging on
  // a decision)
  if (sig_state->last_probe_type == UNPROBED) {
    update_signal_state(prober, state, proto, new_belief_up);
  }

  // update the belief
  sig_state->current_belief = new_belief_up;

  // and the combined signal, after this protocol's probing state is final
  update_combined_signal(prober, s24, state, proto, resp.verdict);

  return 0;

err:
  return -1;
}

static int start_driver(struct driver_wrap *dw, char *driver_name,
                        char *driver_config)
{
  // start user-specified driver
  if ((dw->driver = trinarkular_driver_create_by_name(driver_name,
                                                      driver_config)) == NULL) {
    return -1;
  }

  // add the driver to our event loop
  if (zloop_reader(dw->prober->loop,
                   trinarkular_driver_get_recv_socket(dw->driver),
                   handle_driver_resp, dw) != 0) {
    trinarkular_log("ERROR: Could not add driver to prober event loop");
    return -1;
  }

  return 0;
}

trinarkular_prober_t *trinarkular_prober_create(const char *name,
                                                const char *probelist,
                                                timeseries_t *ts_slash24,
                                                timeseries_t *ts_aggr)
{
  trinarkular_prober_t *prober;

  if ((prober = malloc_zero(sizeof(trinarkular_prober_t))) == NULL) {
    trinarkular_log("ERROR: Could not create prober object");
    return NULL;
  }

  // initialize default params
  set_default_params(&prober->params);

  prober->ts_slash24 = ts_slash24;
  prober->ts_aggr = ts_aggr;

  prober->name = strdup(name);
  assert(prober->name != NULL);
  prober->name_ts = strdup(name);
  assert(prober->name_ts != NULL);
  prober->probelist_filename = strdup(probelist);
  assert(prober->probelist_filename != NULL);

  // prepare and assign probelist
  if (trinarkular_prober_prepare_probelist(prober) != 0) {
    goto err;
  }
  trinarkular_prober_update_probelist(prober);

  // create the reactor
  if ((prober->loop = zloop_new()) == NULL) {
    trinarkular_log("ERROR: Could not initialize reactor");
    goto err;
  }

  trinarkular_log("done");

  return prober;

err:
  trinarkular_prober_destroy(prober);
  return NULL;
}

void trinarkular_prober_destroy(trinarkular_prober_t *prober)
{
  int i;

  if (prober == NULL) {
    return;
  }

  if (PARAM(geoasn_csv_file)) {
    free(PARAM(geoasn_csv_file));
  }
  PARAM(geoasn_csv_file) = NULL;

  free(prober->name);
  prober->name = NULL;
  free(prober->name_ts);
  prober->name_ts = NULL;
  free(prober->probelist_filename);
  prober->probelist_filename = NULL;

  zloop_destroy(&prober->loop);

  if (prober->outstanding_probe_cnt != 0) {
    trinarkular_log("WARN: %d outstanding probes at shutdown",
                    prober->outstanding_probe_cnt);
  }

  // shut down the probe driver(s)
  for (i = 0; i < prober->drivers_cnt; i++) {
    trinarkular_driver_destroy(prober->drivers[i].driver);
  }
  prober->drivers_cnt = 0;

  probelist_state_destroy(&ACTIVE_PL_STATE(prober));
  probelist_state_destroy(&NEXT_PL_STATE(prober));

  // timeseries instances don't belong to us

  free(prober);
}

int trinarkular_prober_start(trinarkular_prober_t *prober)
{
  uint32_t periodic_timeout;
  uint64_t now;
  uint64_t aligned_start;

  assert(prober != NULL);
  assert(prober->started == 0);

  if (ACTIVE_PL(prober) == NULL ||
      trinarkular_probelist_get_slash24_cnt(ACTIVE_PL(prober)) == 0) {
    trinarkular_log("ERROR: Missing or empty probelist. Refusing to start");
    return -1;
  }

  // create the periodic probe timer
  periodic_timeout =
    PARAM(periodic_round_duration) / PARAM(periodic_round_slices);
  if (periodic_timeout < 100) {
    trinarkular_log("WARN: Periodic timer is set to fire every %dms",
                    periodic_timeout);
  }
  if ((prober->periodic_timer_id = zloop_timer(prober->loop, periodic_timeout,
                                               0, handle_timer, prober)) < 0) {
    trinarkular_log("ERROR: Could not create periodic timer");
    return -1;
  }

  // start the default driver if needed
  if (prober->drivers_cnt == 0 &&
      trinarkular_prober_add_driver(prober, TRINARKULAR_PROBER_DRIVER_DEFAULT,
                                    TRINARKULAR_PROBER_DRIVER_ARGS_DEFAULT) !=
        0) {
    return -1;
  }

  prober->started = 1;

  // wait so that our round starts at a nice time
  now = zclock_time();
  aligned_start = (((uint64_t)(now / PARAM(periodic_round_duration))) *
                   PARAM(periodic_round_duration)) +
                  PARAM(periodic_round_duration);

  if (PARAM(sleep_align_start) != 0) {
    trinarkular_log("Sleeping for %d seconds to align with round duration",
                    (aligned_start / 1000) - (now / 1000));
    if (sleep((aligned_start / 1000) - (now / 1000)) != 0) {
      trinarkular_log("WARN: Sleep interrupted, exiting");
    }
  }

  trinarkular_log("prober up and running");

  while (zloop_start(prober->loop) == 0) {
    // Only reenter zloop_start() if we got a SIGHUP.
    if (errno == EINTR && sighup_received) {
      sighup_received = 0;
    } else {
      break;
    }
  }

  return 0;
}

void trinarkular_prober_stop(trinarkular_prober_t *prober)
{
  assert(prober != NULL);

  prober->shutdown = 1;

  trinarkular_log("waiting to shut down");
}

void trinarkular_prober_set_periodic_round_duration(
  trinarkular_prober_t *prober, uint64_t duration)
{
  assert(prober != NULL);

  trinarkular_log("%" PRIu64, duration);
  PARAM(periodic_round_duration) = duration;
}

void trinarkular_prober_set_periodic_round_slices(trinarkular_prober_t *prober,
                                                  int slices)
{
  assert(prober != NULL);

  trinarkular_log("%d", slices);
  PARAM(periodic_round_slices) = slices;
}

void trinarkular_prober_set_periodic_round_limit(trinarkular_prober_t *prober,
                                                 int rounds)
{
  assert(prober != NULL);

  trinarkular_log("%d", rounds);
  PARAM(periodic_round_limit) = rounds;
}

void trinarkular_prober_set_periodic_probe_timeout(trinarkular_prober_t *prober,
                                                   uint32_t timeout)
{
  assert(prober != NULL);
  assert(timeout < UINT8_MAX);

  trinarkular_log("%" PRIu16, timeout);
  PARAM(periodic_probe_timeout) = timeout;
}

void trinarkular_prober_set_geoasn_csv_file(trinarkular_prober_t *prober,
        char *filename) {
  if (PARAM(geoasn_csv_file)) {
    free(PARAM(geoasn_csv_file));
  }
  assert(filename);
  PARAM(geoasn_csv_file) = strdup(filename);
}

void trinarkular_prober_disable_sleep_align_start(trinarkular_prober_t *prober)
{
  assert(prober != NULL);

  PARAM(sleep_align_start) = 0;
}

int trinarkular_prober_add_driver(trinarkular_prober_t *prober,
                                  char *driver_name, char *driver_args)
{
  assert(prober != NULL);

  trinarkular_log("%s %s", driver_name, driver_args);

  prober->drivers[prober->drivers_cnt].id = prober->drivers_cnt;
  prober->drivers[prober->drivers_cnt].prober = prober;

  // initialize the driver
  if (start_driver(&prober->drivers[prober->drivers_cnt], driver_name,
                   driver_args) != 0) {
    return -1;
  }

  prober->drivers_cnt++;

  trinarkular_log("%d drivers", prober->drivers_cnt);

  return 0;
}

void trinarkular_prober_reload_probelist(trinarkular_prober_t *prober)
{
  assert(prober != NULL);

  if (prober->reload_probelist_state != PROBELIST_RELOAD_NONE) {
    trinarkular_log("Probelist reload still in progress.  Ignoring signal.");
  } else {
    prober->reload_probelist_state = PROBELIST_RELOAD_SCHEDULED;
    trinarkular_log("Probelist reload scheduled");
  }
}
