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

#ifndef __TRINARKULAR_PROBELIST_H
#define __TRINARKULAR_PROBELIST_H

#include <stdint.h>
#include "khash.h"
#include "trinarkular_probe.h"
/** @file
 *
 * @brief Header file that exposes the public interface of the trinarkular
 * probelist
 *
 * @author Alistair King
 *
 */

/**
 * @name Public Constants
 *
 * @{ */

/** @} */

/**
 * @name Public Enums
 *
 * @{ */

/** @} */

/**
 * @name Public Opaque Data Structures
 *
 * @{ */

/** Structure representing a trinarkular probe list */
typedef struct trinarkular_probelist trinarkular_probelist_t;

/** @} */

/**
 * @name Public Data Structures
 *
 * @{ */

typedef struct trinarkular_slash24_metrics {

  /** (kp idx) Value will be the 0-100 belief value for the given /24 */
  int32_t belief;

  /** (kp idx) Value will be 0 (uncertain), 1 (down), or 2 (up) */
  int32_t state;

  /** (shared kp idx) Value will be # /24s in each state */
  int32_t overall[3]; // UNCERTAIN, DOWN, UP

} __attribute__((packed)) trinarkular_slash24_metrics_t;

/** Signals kept for each /24: one per probe protocol, at the same index as
 * the protocol, plus a combined signal that every protocol's responses feed.
 */
typedef enum trinarkular_signal_id {

  TRINARKULAR_SIGNAL_ICMP = TRINARKULAR_PROBE_PROTO_ICMP,

  TRINARKULAR_SIGNAL_TCP = TRINARKULAR_PROBE_PROTO_TCP,

  TRINARKULAR_SIGNAL_COMBINED = TRINARKULAR_PROBE_PROTO_CNT,

  TRINARKULAR_SIGNAL_CNT,

} trinarkular_signal_id_t;

/** Bit for a signal in a mask of signals */
#define TRINARKULAR_SIGNAL_BIT(sig) (1 << (sig))

/** Belief state for one signal of a /24 */
typedef struct trinarkular_signal_state {

  /** Index of the current host in this protocol's host list (unused for the
      combined signal, which sends no probes of its own) */
  uint8_t current_host;

  /** What was the type of the last probe sent for this signal? */
  uint8_t last_probe_type;

  /** The number of additional probes that can be sent this round.
   * Since AK is a masochist, the bottom 4 bits are used for the adaptive probe
   * budget and the top 4 are used for the recovery probe budget.  Use the
   * ADAPTIVE_BUDGET and RECOVERY_BUDGET macros...
   */
  uint8_t probe_budget;

  /** The current belief value */
  float current_belief;

  /** Last stable state (Warning: this **may not** match
      BELIEF_STATE(current_belief) if adaptive probing has been used) */
  uint8_t current_state;

  /** How many rounds has it been since this signal was UP? The value is
      incremented *before* sending a periodic probe. Once the value reaches
      255, it is reset to RECOVERY_BACKOFF_MAX to avoid wrapping */
  uint8_t rounds_since_up;

} __attribute__((packed)) trinarkular_signal_state_t;

/** Structure representing prober state for a /24
 *
 * NB: When modifying fields here, you MUST also modify the copy_state function
 * in trinarkular_probelist.c
 */
typedef struct trinarkular_slash24_state {

  /** Belief state per signal (indexed by trinarkular_signal_id_t) */
  trinarkular_signal_state_t sig[TRINARKULAR_SIGNAL_CNT];

  /** Set of timeseries associated with this /24: metrics_cnt per signal, so
      the metrics for signal s and metadata i are at
      metrics[s * metrics_cnt + i] */
  trinarkular_slash24_metrics_t *metrics;

  /** Latency/loss counters, for ICMP probes only */
  uint64_t cumulative_rtt;

  uint32_t probes_sent;

  uint32_t replies_seen;

  int32_t latency_kp_index;

  int32_t loss_kp_index;

  int32_t probes_kp_index;

  /** Number of metric sets per signal */
  uint8_t metrics_cnt;

} __attribute__((packed)) trinarkular_slash24_state_t;

#define ADAPTIVE_BUDGET(sigstate) ((sigstate)->probe_budget & 0x0f)

#define ADAPTIVE_BUDGET_SET(sigstate, val)                                     \
  (sigstate)->probe_budget = ((sigstate)->probe_budget & 0xf0) | ((val)&0x0f)

#define RECOVERY_BUDGET(sigstate) (((sigstate)->probe_budget >> 4) & 0xf)

#define RECOVERY_BUDGET_SET(sigstate, val)                                     \
  (sigstate)->probe_budget =                                                   \
    ((sigstate)->probe_budget & 0x0f) | (((val)&0x0f) << 4)

/** The hosts of a /24 that are probed with one protocol */
typedef struct trinarkular_slash24_hosts {

  /** List of target host bytes (should be OR'd with the network IP) */
  uint8_t *hosts;

  /** Destination port of each host (host byte order), NULL for ICMP */
  uint16_t *ports;

  /** Number of host bytes */
  uint16_t hosts_cnt;

  /** The average response rate of recently responding hosts with this
   * protocol (I.e. the A(E(b)) value from the paper) */
  float aeb;

} __attribute__((packed)) trinarkular_slash24_hosts_t;

typedef struct trinarkular_slash24 {

  /** The network IP (first IP) of this /24 (in host byte order) */
  uint32_t network_ip;

  /** Hosts per probe protocol (indexed by trinarkular_probe_proto_t); a
      protocol with no hosts is not probed in this /24 */
  trinarkular_slash24_hosts_t proto[TRINARKULAR_PROBE_PROTO_CNT];

  /** List of metadata */
  char **md;

  /** Number of items in metadata list */
  uint8_t md_cnt;

} __attribute__((packed)) trinarkular_slash24_t;

/** @} */

/** Create a new Trinarkular Probelist object
 *
 * @return pointer to a probelist object if successful, NULL otherwise
 */
trinarkular_probelist_t *trinarkular_probelist_create(const char *filename);

/** Destroy the given Trinarkular Probelist
 *
 * @param pl            pointer to the probelist to destroy
 */
void trinarkular_probelist_destroy(trinarkular_probelist_t *pl);

/** Get the version of the current probelist
 *
 * @param pl            pointer to the probelist to set version for
 * @return probelist version string
 */
char *trinarkular_probelist_get_version(trinarkular_probelist_t *pl);

/** Get the signals this probelist provides
 *
 * @param pl            pointer to the probelist
 * @return mask of TRINARKULAR_SIGNAL_BIT() values: one bit per probe protocol
 * with hosts in at least one /24, plus the combined signal if the probelist
 * uses the multi-protocol format. A probelist in the original single-protocol
 * format provides the ICMP signal only.
 */
uint8_t trinarkular_probelist_get_signals(trinarkular_probelist_t *pl);

/** How many /24s are in this probelist?
 *
 * @param pl            probelist to get /24 count for
 * @return the number of /24s in the probelist
 */
int trinarkular_probelist_get_slash24_cnt(trinarkular_probelist_t *pl);

/** Reset the iterator to the first /24 in the probelist
 *
 * @param pl            pointer to the probelist to reset
 */
void trinarkular_probelist_reset_slash24_iter(trinarkular_probelist_t *pl);

/** Get the next /24 from the probelist
 *
 * @param pl            pointer to the probelist
 * @return borrowed reference to the next /24 in the probelist or NULL
 * if no /24s remain
 */
trinarkular_slash24_t *
trinarkular_probelist_get_next_slash24(trinarkular_probelist_t *pl);

/** Are there more /24s left to iterate over?
 *
 * @param pl            pointer to the probelist
 * @return 1 if there are more /24s remaining, 0 otherwise
 */
int trinarkular_probelist_has_more_slash24(trinarkular_probelist_t *pl);

/** Get the given /24 from the probelist
 *
 * @param pl            pointer to the probelist
 * @param network_ip    network IP of the /24 to retrieve (host byte order)
 * @return borrowed reference to the next /24 in the probelist or NULL
 * if no /24s remain
 */
trinarkular_slash24_t *
trinarkular_probelist_get_slash24(trinarkular_probelist_t *pl,
                                  uint32_t network_ip);

/** Create a /24 state structure
 *
 * @param metrics_cnt   number of metrics to initialize
 * @return pointer to the state structure created if successful, NULL otherwise
 */
trinarkular_slash24_state_t *trinarkular_slash24_state_create(int metrics_cnt);

/** Destroy the given /24 state structure
 *
 * @param state         pointer to the state structure to destroy
 *
 * Be careful to only call this for state structures that you own. The
 * _get_slash24_state function returns a borrowed pointer that does not need to
 * be freed.
 */
void trinarkular_slash24_state_destroy(trinarkular_slash24_state_t *state);

/** Save state for the given /24
 *
 * @param pl            pointer to a probelist
 * @param s24           pointer to the /24 to save state for
 * @param state         pointer to state to set
 * @return 0 if the state was set successfully, -1 otherwise
 */
int trinarkular_probelist_save_slash24_state(
  trinarkular_probelist_t *pl, trinarkular_slash24_t *s24,
  trinarkular_slash24_state_t *state);

/** Get the state associated with the given /24
 *
 * @param s24           pointer to a /24
 * @return borrowed pointer to the state if set, NULL otherwise
 */
void *trinarkular_probelist_get_slash24_state(trinarkular_probelist_t *pl,
                                              trinarkular_slash24_t *s24);

/** Reset the cumulative latency and probe counters for each /24 in the
 *  probelist.
 *
 *  @param pl           pointer to a probelist
 */
void trinarkular_probelist_reset_slash24_counters(trinarkular_probelist_t *pl);

void *trinarkular_probelist_get_next_slash24_state(
        trinarkular_probelist_t *pl, khiter_t *iter);

void *trinarkular_probelist_get_first_slash24_state(
        trinarkular_probelist_t *pl, khiter_t *iter);

// Helper functions

/** Get the next host of a /24 to probe with the given protocol
 *
 * @param s24           pointer to the /24
 * @param state         pointer to the /24's state
 * @param proto         probe protocol (must have hosts in this /24)
 * @param[out] port     set to the host's destination port (0 for ICMP)
 * @return host IP in host byte order
 */
uint32_t
trinarkular_probelist_get_next_host(trinarkular_slash24_t *s24,
                                    trinarkular_slash24_state_t *state,
                                    int proto, uint16_t *port);

#endif /* __TRINARKULAR_PROBELIST_H */
