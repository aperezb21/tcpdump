#include "anon.h"

void anon_packet(netdissect_options *ndo, const struct pcap_pkthdr *h, u_char *sp, pcap_t *pd)
{

    int dlt;
    struct ip *ip;
    u_short length_type;

	ndo->ndo_snapend = sp + h->caplen;
	ndo->ndo_packetp = sp;
    
    dlt = pcap_datalink(pd);

    switch (dlt)
    {
    case DLT_EN10MB:

        sp += 2 * 6U;
        length_type = GET_BE_U_2(sp);
        sp += 2;
        switch (length_type)
        {
        case ETHERTYPE_IP:

            ip = (struct ip *)sp;
            uint32_t ipsrc = EXTRACT_IPV4_TO_NETWORK_ORDER(ip->ip_src);
            uint32_t ipdst = EXTRACT_IPV4_TO_NETWORK_ORDER(ip->ip_dst);

            uint32_t ipsrcanon = scramble_ip4(ipsrc, 0);
            uint32_t ipdstanon = scramble_ip4(ipdst, 0);

            memcpy(ip->ip_src, &ipsrcanon, sizeof(uint32_t));
            memcpy(ip->ip_dst, &ipdstanon, sizeof(uint32_t));
            break;
        }
    }
}