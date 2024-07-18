#include "netdissect.h"
#include "netdissect-stdinc.h"
#include <pcap.h>
#include <cryptopANT.h>
#include "netdissect.h"
#include "ip.h"
#include "ethertype.h"
#include "extract.h"
#include "gre.h"
#include "ipproto.h"

#define ar_spa_anon(ap)	(((u_char *)((ap)+1))+  GET_U_1((ap)->ar_hln))
#define ar_tpa_anon(ap)	(((u_char *)((ap)+1))+2*GET_U_1((ap)->ar_hln)+GET_U_1((ap)->ar_pln))
#define SPA_ANON(ap) (ar_spa_anon(ap))
#define TPA_ANON(ap) (ar_tpa_anon(ap))

#define IS_BROADCAST_IP4 4294967295
#define IS_ZERO_IP4 0

void anon_packet(netdissect_options *, const struct pcap_pkthdr *, u_char *, pcap_t *, int, int);
extern uint32_t (*anon_ipv4_func_ptr)(uint32_t, int);
extern void (*anon_ipv6_func_ptr)(struct in6_addr *, int);