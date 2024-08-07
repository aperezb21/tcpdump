

struct icmp6_hdr {
	nd_uint8_t	icmp6_type;	/* type field */
	nd_uint8_t	icmp6_code;	/* code field */
	nd_uint16_t	icmp6_cksum;	/* checksum field */
	union {
		nd_uint32_t	icmp6_un_data32[1]; /* type-specific field */
		nd_uint16_t	icmp6_un_data16[2]; /* type-specific field */
		nd_uint8_t	icmp6_un_data8[4];  /* type-specific field */
		nd_byte		icmp6_un_data[1];   /* type-specific field */
	} icmp6_dataun;
};


#define icmp6_data32	icmp6_dataun.icmp6_un_data32
#define icmp6_data16	icmp6_dataun.icmp6_un_data16
#define icmp6_data8	icmp6_dataun.icmp6_un_data8
#define icmp6_data	icmp6_dataun.icmp6_un_data
#define icmp6_pptr	icmp6_data32[0]		/* parameter prob */
#define icmp6_mtu	icmp6_data32[0]		/* packet too big */
#define icmp6_id	icmp6_data16[0]		/* echo request/reply */
#define icmp6_seq	icmp6_data16[1]		/* echo request/reply */
#define icmp6_maxdelay	icmp6_data16[0]		/* mcast group membership */

#define ICMP6_DST_UNREACH		1	/* dest unreachable, codes: */
#define ICMP6_PACKET_TOO_BIG		2	/* packet too big */
#define ICMP6_TIME_EXCEEDED		3	/* time exceeded, code: */
#define ICMP6_PARAM_PROB		4	/* ip6 header bad */

#define ICMP6_ECHO_REQUEST		128	/* echo service */
#define ICMP6_ECHO_REPLY		129	/* echo reply */
#define ICMP6_MEMBERSHIP_QUERY		130	/* group membership query */
#define MLD6_LISTENER_QUERY		130	/* multicast listener query */
#define ICMP6_MEMBERSHIP_REPORT		131	/* group membership report */
#define MLD6_LISTENER_REPORT		131	/* multicast listener report */
#define ICMP6_MEMBERSHIP_REDUCTION	132	/* group membership termination */
#define MLD6_LISTENER_DONE		132	/* multicast listener done */

#define ND_ROUTER_SOLICIT		133	/* router solicitation */
#define ND_ROUTER_ADVERT		134	/* router advertisement */
#define ND_NEIGHBOR_SOLICIT		135	/* neighbor solicitation */
#define ND_NEIGHBOR_ADVERT		136	/* neighbor advertisement */
#define ND_REDIRECT			137	/* redirect */

#define ICMP6_ROUTER_RENUMBERING	138	/* router renumbering */

#define ICMP6_WRUREQUEST		139	/* who are you request */
#define ICMP6_WRUREPLY			140	/* who are you reply */
#define ICMP6_FQDN_QUERY		139	/* FQDN query */
#define ICMP6_FQDN_REPLY		140	/* FQDN reply */
#define ICMP6_NI_QUERY			139	/* node information request - RFC 4620 */
#define ICMP6_NI_REPLY			140	/* node information reply - RFC 4620 */
#define IND_SOLICIT			141	/* inverse neighbor solicitation */
#define IND_ADVERT			142	/* inverse neighbor advertisement */

#define ICMP6_V2_MEMBERSHIP_REPORT	143	/* v2 membership report */
#define MLDV2_LISTENER_REPORT		143	/* v2 multicast listener report */
#define ICMP6_HADISCOV_REQUEST		144
#define ICMP6_HADISCOV_REPLY		145
#define ICMP6_MOBILEPREFIX_SOLICIT	146
#define ICMP6_MOBILEPREFIX_ADVERT	147

#define MLD6_MTRACE_RESP		200	/* mtrace response(to sender) */
#define MLD6_MTRACE			201	/* mtrace messages */

#define ICMP6_MAXTYPE			201

#define ICMP6_DST_UNREACH_NOROUTE	0	/* no route to destination */
#define ICMP6_DST_UNREACH_ADMIN		1	/* administratively prohibited */
#define ICMP6_DST_UNREACH_NOTNEIGHBOR	2	/* not a neighbor(obsolete) */
#define ICMP6_DST_UNREACH_BEYONDSCOPE	2	/* beyond scope of source address */
#define ICMP6_DST_UNREACH_ADDR		3	/* address unreachable */
#define ICMP6_DST_UNREACH_NOPORT	4	/* port unreachable */

#define ICMP6_TIME_EXCEED_TRANSIT	0	/* ttl==0 in transit */
#define ICMP6_TIME_EXCEED_REASSEMBLY	1	/* ttl==0 in reass */

#define ICMP6_PARAMPROB_HEADER		0	/* erroneous header field */
#define ICMP6_PARAMPROB_NEXTHEADER	1	/* unrecognized next header */
#define ICMP6_PARAMPROB_OPTION		2	/* unrecognized option */
#define ICMP6_PARAMPROB_FRAGHDRCHAIN	3	/* incomplete header chain */

#define ICMP6_INFOMSG_MASK		0x80	/* all informational messages */

#define ICMP6_NI_SUBJ_IPV6	0	/* Query Subject is an IPv6 address */
#define ICMP6_NI_SUBJ_FQDN	1	/* Query Subject is a Domain name */
#define ICMP6_NI_SUBJ_IPV4	2	/* Query Subject is an IPv4 address */

#define ICMP6_NI_SUCCESS	0	/* node information successful reply */
#define ICMP6_NI_REFUSED	1	/* node information request is refused */
#define ICMP6_NI_UNKNOWN	2	/* unknown Qtype */

#define ICMP6_ROUTER_RENUMBERING_COMMAND  0	/* rr command */
#define ICMP6_ROUTER_RENUMBERING_RESULT   1	/* rr result */
#define ICMP6_ROUTER_RENUMBERING_SEQNUM_RESET   255	/* rr seq num reset */

/* Used in kernel only */
#define ND_REDIRECT_ONLINK	0	/* redirect to an on-link node */
#define ND_REDIRECT_ROUTER	1	/* redirect to a better router */



/*
 * Multicast Listener Discovery
 */
struct mld6_hdr {
	struct icmp6_hdr	mld6_hdr;
	nd_ipv6			mld6_addr; /* multicast address */
};

#define mld6_type	mld6_hdr.icmp6_type
#define mld6_code	mld6_hdr.icmp6_code
#define mld6_cksum	mld6_hdr.icmp6_cksum
#define mld6_maxdelay	mld6_hdr.icmp6_data16[0]
#define mld6_reserved	mld6_hdr.icmp6_data16[1]

#define MLD_MINLEN	24
#define MLDV2_MINLEN	28

/*
 * Neighbor Discovery
 */

struct nd_router_solicit {	/* router solicitation */
	struct icmp6_hdr	nd_rs_hdr;
	/* could be followed by options */
};

#define nd_rs_type	nd_rs_hdr.icmp6_type
#define nd_rs_code	nd_rs_hdr.icmp6_code
#define nd_rs_cksum	nd_rs_hdr.icmp6_cksum
#define nd_rs_reserved	nd_rs_hdr.icmp6_data32[0]

struct nd_router_advert {	/* router advertisement */
	struct icmp6_hdr	nd_ra_hdr;
	nd_uint32_t		nd_ra_reachable;	/* reachable time */
	nd_uint32_t		nd_ra_retransmit;	/* retransmit timer */
	/* could be followed by options */
};

#define nd_ra_type		nd_ra_hdr.icmp6_type
#define nd_ra_code		nd_ra_hdr.icmp6_code
#define nd_ra_cksum		nd_ra_hdr.icmp6_cksum
#define nd_ra_curhoplimit	nd_ra_hdr.icmp6_data8[0]
#define nd_ra_flags_reserved	nd_ra_hdr.icmp6_data8[1]
#define ND_RA_FLAG_MANAGED	0x80
#define ND_RA_FLAG_OTHER	0x40
#define ND_RA_FLAG_HOME_AGENT	0x20
#define ND_RA_FLAG_IPV6ONLY	0x02

/*
 * Router preference values based on draft-draves-ipngwg-router-selection-01.
 * These are non-standard definitions.
 */
#define ND_RA_FLAG_RTPREF_MASK	0x18 /* 00011000 */

#define ND_RA_FLAG_RTPREF_HIGH	0x08 /* 00001000 */
#define ND_RA_FLAG_RTPREF_MEDIUM	0x00 /* 00000000 */
#define ND_RA_FLAG_RTPREF_LOW	0x18 /* 00011000 */
#define ND_RA_FLAG_RTPREF_RSV	0x10 /* 00010000 */

#define nd_ra_router_lifetime	nd_ra_hdr.icmp6_data16[1]

struct nd_neighbor_solicit {	/* neighbor solicitation */
	struct icmp6_hdr	nd_ns_hdr;
	nd_ipv6			nd_ns_target;	/*target address */
	/* could be followed by options */
};

#define nd_ns_type		nd_ns_hdr.icmp6_type
#define nd_ns_code		nd_ns_hdr.icmp6_code
#define nd_ns_cksum		nd_ns_hdr.icmp6_cksum
#define nd_ns_reserved		nd_ns_hdr.icmp6_data32[0]

struct nd_neighbor_advert {	/* neighbor advertisement */
	struct icmp6_hdr	nd_na_hdr;
	nd_ipv6			nd_na_target;	/* target address */
	/* could be followed by options */
};

#define nd_na_type		nd_na_hdr.icmp6_type
#define nd_na_code		nd_na_hdr.icmp6_code
#define nd_na_cksum		nd_na_hdr.icmp6_cksum
#define nd_na_flags_reserved	nd_na_hdr.icmp6_data32[0]

#define ND_NA_FLAG_ROUTER		0x80000000
#define ND_NA_FLAG_SOLICITED		0x40000000
#define ND_NA_FLAG_OVERRIDE		0x20000000

struct nd_redirect {		/* redirect */
	struct icmp6_hdr	nd_rd_hdr;
	nd_ipv6			nd_rd_target;	/* target address */
	nd_ipv6			nd_rd_dst;	/* destination address */
	/* could be followed by options */
};

#define nd_rd_type		nd_rd_hdr.icmp6_type
#define nd_rd_code		nd_rd_hdr.icmp6_code
#define nd_rd_cksum		nd_rd_hdr.icmp6_cksum
#define nd_rd_reserved		nd_rd_hdr.icmp6_data32[0]

struct nd_opt_hdr {		/* Neighbor discovery option header */
	nd_uint8_t	nd_opt_type;
	nd_uint8_t	nd_opt_len;
	/* followed by option specific data*/
};

#define ND_OPT_SOURCE_LINKADDR		1
#define ND_OPT_TARGET_LINKADDR		2
#define ND_OPT_PREFIX_INFORMATION	3
#define ND_OPT_REDIRECTED_HEADER	4
#define ND_OPT_MTU			5
#define ND_OPT_ADVINTERVAL		7
#define ND_OPT_HOMEAGENT_INFO		8
#define ND_OPT_ROUTE_INFO		24	/* RFC4191 */
#define ND_OPT_RDNSS			25
#define ND_OPT_DNSSL			31

struct nd_opt_prefix_info {	/* prefix information */
	nd_uint8_t	nd_opt_pi_type;
	nd_uint8_t	nd_opt_pi_len;
	nd_uint8_t	nd_opt_pi_prefix_len;
	nd_uint8_t	nd_opt_pi_flags_reserved;
	nd_uint32_t	nd_opt_pi_valid_time;
	nd_uint32_t	nd_opt_pi_preferred_time;
	nd_uint32_t	nd_opt_pi_reserved2;
	nd_ipv6		nd_opt_pi_prefix;
};

#define ND_OPT_PI_FLAG_ONLINK		0x80
#define ND_OPT_PI_FLAG_AUTO		0x40
#define ND_OPT_PI_FLAG_ROUTER		0x20	/*2292bis*/

struct nd_opt_rd_hdr {         /* redirected header */
	nd_uint8_t	nd_opt_rh_type;
	nd_uint8_t	nd_opt_rh_len;
	nd_uint16_t	nd_opt_rh_reserved1;
	nd_uint32_t	nd_opt_rh_reserved2;
	/* followed by IP header and data */
};

struct nd_opt_mtu {		/* MTU option */
	nd_uint8_t	nd_opt_mtu_type;
	nd_uint8_t	nd_opt_mtu_len;
	nd_uint16_t	nd_opt_mtu_reserved;
	nd_uint32_t	nd_opt_mtu_mtu;
};

struct nd_opt_rdnss {		/* RDNSS RFC 6106 5.1 */
	nd_uint8_t	nd_opt_rdnss_type;
	nd_uint8_t	nd_opt_rdnss_len;
	nd_uint16_t	nd_opt_rdnss_reserved;
	nd_uint32_t	nd_opt_rdnss_lifetime;
	nd_ipv6		nd_opt_rdnss_addr[1];	/* variable-length */
};

struct nd_opt_dnssl {		/* DNSSL RFC 6106 5.2 */
	nd_uint8_t  nd_opt_dnssl_type;
	nd_uint8_t  nd_opt_dnssl_len;
	nd_uint16_t nd_opt_dnssl_reserved;
	nd_uint32_t nd_opt_dnssl_lifetime;
	/* followed by list of DNS search domains, variable-length */
};

struct nd_opt_advinterval {	/* Advertisement interval option */
	nd_uint8_t	nd_opt_adv_type;
	nd_uint8_t	nd_opt_adv_len;
	nd_uint16_t	nd_opt_adv_reserved;
	nd_uint32_t	nd_opt_adv_interval;
};

struct nd_opt_homeagent_info {	/* Home Agent info */
	nd_uint8_t	nd_opt_hai_type;
	nd_uint8_t	nd_opt_hai_len;
	nd_uint16_t	nd_opt_hai_reserved;
	nd_uint16_t	nd_opt_hai_preference;
	nd_uint16_t	nd_opt_hai_lifetime;
};

struct nd_opt_route_info {	/* route info */
	nd_uint8_t	nd_opt_rti_type;
	nd_uint8_t	nd_opt_rti_len;
	nd_uint8_t	nd_opt_rti_prefixlen;
	nd_uint8_t	nd_opt_rti_flags;
	nd_uint32_t	nd_opt_rti_lifetime;
	/* prefix follows */
};