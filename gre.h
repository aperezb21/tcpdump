/*	$OpenBSD: print-gre.c,v 1.6 2002/10/30 03:04:04 fgsch Exp $	*/

/*
 * Copyright (c) 2002 Jason L. Wright (jason@thought.net)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* \summary: Header flags for Generic Routing Encapsulation (GRE) */

#define	GRE_CP		0x8000		/* checksum present */
#define	GRE_RP		0x4000		/* routing present */
#define	GRE_KP		0x2000		/* key present */
#define	GRE_SP		0x1000		/* sequence# present */
#define	GRE_sP		0x0800		/* source routing */
#define	GRE_AP		0x0080		/* acknowledgment# present */



#define	GRE_RECRS_MASK	0x0700		/* recursion count */
#define	GRE_VERS_MASK	0x0007		/* protocol version */

/*
 * Ethertype values used for GRE (but not elsewhere?).
 */
#define GRE_CDP			0x2000	/* Cisco Discovery Protocol */
#define GRE_NHRP		0x2001	/* Next Hop Resolution Protocol */
#define GRE_MIKROTIK_EOIP	0x6400	/* MikroTik RouterBoard Ethernet over IP (EoIP) */
#define GRE_ERSPAN_III		0x22eb
#define GRE_WCCP		0x883e	/* Web Cache C* Protocol */
#define GRE_ERSPAN_I_II		0x88be
