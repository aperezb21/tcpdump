
#include "netdissect-stdinc.h"


#include "netdissect.h"

struct bootp {
	nd_uint8_t	bp_op;		/* packet opcode type */
	nd_uint8_t	bp_htype;	/* hardware addr type */
	nd_uint8_t	bp_hlen;	/* hardware addr length */
	nd_uint8_t	bp_hops;	/* gateway hops */
	nd_uint32_t	bp_xid;		/* transaction ID */
	nd_uint16_t	bp_secs;	/* seconds since boot began */
	nd_uint16_t	bp_flags;	/* flags - see bootp_flag_values[]
					   in print-bootp.c */
	nd_ipv4		bp_ciaddr;	/* client IP address */
	nd_ipv4		bp_yiaddr;	/* 'your' IP address */
	nd_ipv4		bp_siaddr;	/* server IP address */
	nd_ipv4		bp_giaddr;	/* gateway IP address */
	nd_byte		bp_chaddr[16];	/* client hardware address */
	nd_byte		bp_sname[64];	/* server host name */
	nd_byte		bp_file[128];	/* boot file name */
	nd_byte		bp_vend[64];	/* vendor-specific area */
};

#define	TAG_REQUESTED_IP	((uint8_t)  50)
#define	TAG_IP_LEASE		((uint8_t)  51)
#define	TAG_OPT_OVERLOAD	((uint8_t)  52)
#define	TAG_TFTP_SERVER		((uint8_t)  66)
#define	TAG_BOOTFILENAME	((uint8_t)  67)
#define	TAG_DHCP_MESSAGE	((uint8_t)  53)
#define	TAG_SERVER_ID		((uint8_t)  54)
#define	TAG_PARM_REQUEST	((uint8_t)  55)
#define	TAG_MESSAGE		((uint8_t)  56)
#define	TAG_MAX_MSG_SIZE	((uint8_t)  57)
#define	TAG_RENEWAL_TIME	((uint8_t)  58)
#define	TAG_REBIND_TIME		((uint8_t)  59)
#define	TAG_VENDOR_CLASS	((uint8_t)  60)
#define	TAG_CLIENT_ID		((uint8_t)  61)
#define TAG_END			((uint8_t) 255)
#define TAG_PAD			((uint8_t)   0)
