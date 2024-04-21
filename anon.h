#include "netdissect.h"
#include "netdissect-stdinc.h"
#include <pcap.h>
#include <cryptopANT.h>
#include "netdissect.h"
#include "ip.h"
#include "ethertype.h"
#include "extract.h"

void anon_packet(netdissect_options *, const struct pcap_pkthdr *, u_char *, pcap_t *);