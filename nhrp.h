#include "netdissect-stdinc.h"


#include "netdissect.h"


#define NHRP_VER_RFC2332		1

#define NHRP_PKT_RESOLUTION_REQUEST	1
#define NHRP_PKT_RESOLUTION_REPLY	2
#define NHRP_PKT_REGISTRATION_REQUEST	3
#define NHRP_PKT_REGISTRATION_REPLY	4
#define NHRP_PKT_PURGE_REQUEST		5
#define NHRP_PKT_PURGE_REPLY		6
#define NHRP_PKT_ERROR_INDICATION	7
#define NHRP_PKT_TRAFFIC_INDICATION	8 /* draft-detienne-dmvpn-01 */


#define NHRP_RES_ADDR_EXT	 /* draft-detienne-dmvpn-01 */

static const struct tok pkt_types[] = {
	{ NHRP_PKT_RESOLUTION_REQUEST,   "res request" },
	{ NHRP_PKT_RESOLUTION_REPLY,     "res reply" },
	{ NHRP_PKT_REGISTRATION_REQUEST, "reg request" },
	{ NHRP_PKT_REGISTRATION_REPLY,   "reg reply" },
	{ NHRP_PKT_PURGE_REQUEST,        "purge request" },
	{ NHRP_PKT_PURGE_REPLY,          "purge reply" },
	{ NHRP_PKT_ERROR_INDICATION,     "error indication" },
	{ NHRP_PKT_TRAFFIC_INDICATION,   "traffic indication" },
	{ 0, NULL }
};

/*
 * Fixed header part.
 */
struct nhrp_fixed_header {
	nd_uint16_t	afn;		/* link layer address */
	nd_uint16_t	pro_type;	/* protocol type (short form) */
	nd_uint8_t	pro_snap[5];	/* protocol type (long form) */
	nd_uint8_t	hopcnt;		/* hop count */
	nd_uint16_t	pktsz;		/* length of the NHRP packet (octets) */
	nd_uint16_t	chksum;		/* IP checksum over the entier packet */
	nd_uint16_t	extoff;		/* extension offset */
	nd_uint8_t	op_version;	/* version of address mapping and
					   management protocol */
	nd_uint8_t	op_type;	/* NHRP packet type */
	nd_uint8_t	shtl;		/* type and length of src NBMA addr */
	nd_uint8_t	sstl;		/* type and length of src NBMA
					   subaddress */
};

/*
 * Mandatory header part.  This is the beginning of the mandatory
 * header; it's followed by addresses and client information entries.
 *
 * The mandatory header part formats are similar for
 * all NHRP packets; the only difference is that NHRP_PKT_ERROR_INDICATION
 * has a 16-bit error code and a 16-bit error packet offset, and
 * NHRP_PKT_TRAFFIC_INDICATION has a 16-bit traffic code and a 16-bit unused
 * field, rather than a 32-bit request ID.
 */
struct nhrp_mand_header {
	nd_uint8_t	spl;		/* src proto len */
	nd_uint8_t	dpl;		/* dst proto len */
	nd_uint16_t	flags;		/* flags */
        union {
		nd_uint32_t	id;	/* request id */
		struct {		/* error code */
			nd_uint16_t	code;
			nd_uint16_t	offset;
		} err;
		struct {		/* error code */
			nd_uint16_t	traffic_code;
			nd_uint16_t	unused;
		} tind;
	} u;
};

static const struct tok err_code_types[] = {
	{ 1,  "unrecognized extension" },
	{ 3,  "NHRP loop detected" },
	{ 6,  "protocol address unreachable" },
	{ 7,  "protocol error" },
	{ 8,  "NHRP SDU size exceeded" },
	{ 9,  "invalid extension" },
	{ 10, "invalid NHRP resolution reply received" },
	{ 11, "authentication failure" },
	{ 15, "hop count exceeded" },
	{ 0, NULL }
};

static const struct tok traffic_code_types[] = {
	{ 0, "NHRP traffic redirect/indirection" },
	{ 0, NULL }
};

#define NHRP_FIXED_HEADER_LEN			20

struct nhrp_cie {
	/* client information entry */
	nd_uint8_t	code;
	nd_uint8_t	plen;
	nd_uint16_t	unused;
	nd_uint16_t	mtu;
	nd_uint16_t	htime;
	nd_uint8_t	cli_addr_tl;
	nd_uint8_t	cli_saddr_tl;
	nd_uint8_t	cli_proto_tl;
	nd_uint8_t	pref;
};


//Extensio types
#define	RESPONDER_ADDR_EXT	0x8003
#define	FORWARD_TRANSIT_EXT	0x8004
#define	REVERSE_TRANSIT_EXT	0x8005
#define	NHRP_AUTHENTICATION_EXT	0x8007

