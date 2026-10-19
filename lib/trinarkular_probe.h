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

#ifndef __TRINARKULAR_PROBE_H
#define __TRINARKULAR_PROBE_H

#include <stdint.h>
#include <stdio.h>

/** @file
 *
 * @brief Header file that exposes the public interface of the trinarkular probe
 * objects (both requests and responses)
 *
 * @author Alistair King
 *
 */

/* NB: if changing any of these structures, IO functions must also be updated */

/** Protocols a probe can use. ICMP must stay 0: requests that do not set a
 * protocol are ICMP, as they were before protocols existed. */
typedef enum trinarkular_probe_proto {

  /** ICMP echo request */
  TRINARKULAR_PROBE_PROTO_ICMP = 0,

  /** TCP SYN to the request's port */
  TRINARKULAR_PROBE_PROTO_TCP = 1,

  /** Number of probe protocols */
  TRINARKULAR_PROBE_PROTO_CNT = 2,

} trinarkular_probe_proto_t;

/** Structure used when making a probe request to a driver */
typedef struct trinarkular_probe_req {

  /** The target of the probe (network byte order) */
  uint32_t target_ip;

#if 0 /* 2016-03-17 -- AK decides that retrying probes doesn't make sense */
  /** Maximum number of probes to send */
  uint8_t probecount;
#endif

  /** Number of seconds to wait for a reply */
  uint8_t wait;

  /** The protocol to probe with (trinarkular_probe_proto_t) */
  uint8_t proto;

  /** Destination port (host byte order), 0 for ICMP */
  uint16_t port;

} __attribute__((packed)) trinarkular_probe_req_t;

/** The overall verdict of the probe */
typedef enum trinarkular_probe_resp_verdict {

  /** No responses were received to the probe packet(s) */
  TRINARKULAR_PROBE_UNRESPONSIVE = 0,

  /** At least one response was received to a probe packet */
  TRINARKULAR_PROBE_RESPONSIVE = 1,

} trinarkular_probe_resp_verdict_t;

/** Structure returned by driver when a probe is complete */
typedef struct trinarkular_probe_resp {

  /** The IP that was probed (network byte order) */
  uint32_t target_ip;

  /** The overall probe verdict */
  uint8_t verdict;

  /** The RTT of the first response received */
  uint32_t rtt;

  /** The number of probes that were sent in total */
  uint8_t probes_sent;

  /** The number of probes that were responded to in total */
  uint8_t probes_replied;

  /** The protocol of the request (echoed by the driver) */
  uint8_t proto;

  /** The port of the request (echoed by the driver) */
  uint16_t port;

} __attribute__((packed)) trinarkular_probe_resp_t;

/** Print a human-readable version of the given request to the given file handle
 *
 * @param fh            file handle to write to (e.g. stdout)
 * @param req           pointer to the request to dump
 */
void trinarkular_probe_req_fprint(FILE *fh, trinarkular_probe_req_t *req);

/** Print a human-readable version of the given response to the given file
 * handle
 *
 * @param fh            file handle to write to (e.g. stdout)
 * @param resp          pointer to the response to dump
 */
void trinarkular_probe_resp_fprint(FILE *fh, trinarkular_probe_resp_t *resp);

#endif /* __TRINARKULAR_PROBE_H */
