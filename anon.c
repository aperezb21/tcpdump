#include <anon.h>
#include <arp.h>
#include <udp.h>
#include <bootp.h>
#include <icmp6.h>
#include <nameser.h>
#include <nhrp.h>
#include <af.h>

int pass_bits4_const = 0;
int pass_bits6_const = 0;

void anon_ip4(unsigned char *ip)
{

    uint32_t ip4_net_ord = EXTRACT_IPV4_TO_NETWORK_ORDER(ip);
    if (ip4_net_ord != IS_BROADCAST_IP4 && ip4_net_ord != IS_ZERO_IP4)
    {
        uint32_t anon_ip = anon_ipv4_func_ptr(ip4_net_ord, pass_bits4_const);
        memcpy(ip, &anon_ip, sizeof(uint32_t));
    }
}

void anon_ip6(unsigned char *ip)
{

    struct in6_addr ip6_net_ord = EXTRACT_IPV6_TO_NETWORK_ORDER(ip);
    anon_ipv6_func_ptr(&ip6_net_ord, pass_bits6_const);
    memcpy(ip, &ip6_net_ord, sizeof(struct in6_addr));
}


uint8_t skip_ip6_extensions(netdissect_options *ndo, u_char **sp, uint8_t nh){

    

struct ip6_hbh *hbh;
            uint8_t ip6_ext_len;
            struct ip6_frag *fragh;
            int found_extension_header = 1;
            while (found_extension_header)
            {

                switch (nh)
                {
                case IPPROTO_NONE:
                case IPPROTO_HOPOPTS:
                case IPPROTO_DSTOPTS:
                case IPPROTO_ROUTING:
                    hbh = (struct ip6_hbh *)*sp;
                    nh = GET_U_1(hbh->ip6h_nxt);
                    ip6_ext_len = (GET_U_1(hbh->ip6h_len) + 1) << 3;
                    *sp += ip6_ext_len;
                    break;

                case IPPROTO_FRAGMENT:

                    fragh = (struct ip6_frag *)*sp;
                    nh = GET_U_1(fragh->ip6f_nxt);
                    ip6_ext_len = sizeof(struct ip6_frag);
                    *sp += sizeof(struct ip6_frag);
                    break;

                default:
                    found_extension_header = 0;
                    break;
                }
            }

            return nh;

}

void anon_packet(netdissect_options *ndo, const struct pcap_pkthdr *h, u_char *sp, pcap_t *pd, int pass_bits4, int pass_bits6)
{

    int dlt;
    struct ip *ip;
    struct ip6_hdr *ip6;
    u_short length_type;
    uint8_t nh;
    uint16_t sport, dport;
    struct udphdr *up;
    const dns_header_t *np;
    struct bootp *bp;
    u_char *bp_vendor;
    u_int qdcount, ancount, nscount, arcount;
    uint16_t flags, rcode;
    u_char character;
    u_short typ, length;
    u_int len;
    u_int ulen;
    uint16_t tag;
    uint32_t payload_len;
    struct nd_neighbor_solicit *p;
    struct nd_neighbor_advert *p2;
    struct nd_opt_rdnss *oprd;
    struct nd_opt_hdr *op;
    uint8_t opt_type;
    u_int opt_len;
    struct nd_opt_prefix_info *opp;
    uint8_t icmp6_type;
    struct icmp6_hdr *dp;
    struct ip6_hbh *hbh;
    struct ip6_frag *fragh;
    u_int group, nsrcs, ngroups;
    struct mld6_hdr *mp;
    size_t l;
    u_int vers;
    uint16_t prot;

    ndo->ndo_snapend = sp + h->caplen;
    ndo->ndo_packetp = sp;

    pass_bits4_const = pass_bits4;
    pass_bits6_const = pass_bits6;

    dlt = pcap_datalink(pd);

    switch (dlt)
    {
    case DLT_EN10MB:

        // Skip src and dst MAC addresses
        sp += 2 * 6U;
        length_type = GET_BE_U_2(sp);
        // Skip Ethertype
        sp += 2;

        switch (length_type)
        {

        // Skip vlan tag if any
        case ETHERTYPE_8021Q:
        case ETHERTYPE_8021Q9100:
        case ETHERTYPE_8021Q9200:
        case ETHERTYPE_8021QinQ:

            // In case of double tagging, check the next type
            while (length_type == ETHERTYPE_8021Q ||
                   length_type == ETHERTYPE_8021Q9100 ||
                   length_type == ETHERTYPE_8021Q9200 ||
                   length_type == ETHERTYPE_8021QinQ)
            {
                length_type = GET_BE_U_2(sp + 2);
                sp += 4;
            }

        case ETHERTYPE_IP:

            ip = (struct ip *)sp;
            anon_ip4(ip->ip_dst);
            anon_ip4(ip->ip_src);

            // If there is next header fetch it
            len = GET_BE_U_2(ip->ip_len);
            if (len > IP_HL(ip))
            {
                // Get Protocol
                nh = GET_U_1(ip->ip_p);
                sp += IP_HL(ip) * 4;
            }
            break;

        case ETHERTYPE_IPV6:

            ip6 = (struct ip6_hdr *)sp;
            anon_ip6(ip6->ip6_dst);
            anon_ip6(ip6->ip6_src);

            payload_len = GET_BE_U_2(ip6->ip6_plen);

            // Get Next Protocol
            nh = GET_U_1(ip6->ip6_nxt);
            sp += sizeof(struct ip6_hdr);
         
            nh = skip_ip6_extensions(ndo, &sp, nh);
            break;

        case ETHERTYPE_ARP:
        case ETHERTYPE_REVARP:

            struct arp_pkthdr *arp;
            arp = (struct arp_pkthdr *)sp;
            anon_ip4(SPA_ANON(arp));
            anon_ip4(TPA_ANON(arp));
            break;
        }

        //Case there is a GRE packet
        if (nh == IPPROTO_GRE)
        {

            vers = GET_BE_U_2(sp) & GRE_VERS_MASK;
            //Skip the GRE header
            switch (vers)
            {
            case 0:
                flags = GET_BE_U_2(sp);
                sp += 2;
                prot = GET_BE_U_2(sp);
                sp += 2;
                if (flags & GRE_CP)
                {
                    // Skip Checksum and Reserved
                    sp += 4;
                }

                if (flags & GRE_KP)
                {
                    // Skip key
                    sp += 4;
                }
                if (flags & GRE_SP)
                {
                    // Skip sequence
                    sp += 4;
                }
                if (flags & GRE_RP)
                {
                    // Skip routing
                    for (;;)
                    {
                        uint16_t af;
                        uint8_t sreoff;
                        uint8_t srelen;

                        af = GET_BE_U_2(sp);
                        sreoff = GET_U_1(sp + 2);
                        srelen = GET_U_1(sp + 3);
                        sp += 4;

                        if (af == 0 && srelen == 0)
                            break;
                        sp += srelen;
                    }
                }
                break;
            case 1:
                flags = GET_BE_U_2(sp);
                sp += 2;
                prot = GET_BE_U_2(sp);
                sp += 2;

                if (flags & GRE_KP)
                {
                    sp += 4;
                }
                if (flags & GRE_SP)
                {
                    sp += 4;
                }
                if (flags & GRE_AP)
                {
                    sp += 4;
                }
                break;
            default:
                break;
            }
            //Protocol after the GRE header
            switch (prot)
            {
            case ETHERTYPE_IP:
                ip = (struct ip *)sp;
                anon_ip4(ip->ip_src);
                anon_ip4(ip->ip_dst);

                // If there is next header fetch it
                len = GET_BE_U_2(ip->ip_len);
                if (len > IP_HL(ip))
                {
                    // Get Protocol
                    nh = GET_U_1(ip->ip_p);
                    sp += IP_HL(ip) * 4;
                }
                break;

            case ETHERTYPE_IPV6:
                ip6 = (struct ip6_hdr *)sp;
                anon_ip6(ip6->ip6_src);
                anon_ip6(ip6->ip6_dst);

                payload_len = GET_BE_U_2(ip6->ip6_plen);

                // Get Next Protocol
                nh = GET_U_1(ip6->ip6_nxt);
                sp += sizeof(struct ip6_hdr);
                nh = skip_ip6_extensions(ndo, &sp, nh);
                break;

            case GRE_NHRP:
                struct nhrp_fixed_header *fixed_hdr;
                struct nhrp_mand_header *mand_hdr;
                uint16_t pktsz;
                uint16_t extoff;
                uint16_t mand_part_len;
                uint8_t shtl, sstl;
                uint8_t spl, dpl;
                uint16_t afn;
                uint16_t pro_type;
                fixed_hdr = (struct nhrp_fixed_header *)sp;
                afn = GET_BE_U_2(fixed_hdr->afn);
                pro_type = GET_BE_U_2(fixed_hdr->pro_type);
                pktsz = GET_BE_U_2(fixed_hdr->pktsz);
                extoff = GET_BE_U_2(fixed_hdr->extoff);
                uint16_t nhrp_exts_length;
                uint8_t op_type;
                op_type = GET_U_1(fixed_hdr->op_type);
                u_int cie_len;

                struct nhrp_cie *cie;
                uint8_t cli_addr_tl;
                uint8_t cli_saddr_tl;
                uint8_t cli_proto_tl;

                uint32_t ip_dst_p1;
                uint32_t ip_dst_p1_anon;
                struct in6_addr ipdst6p2;

                //Get length of the mandatory part
                if (extoff == 0)
                {
                    mand_part_len = pktsz - sizeof(*fixed_hdr);
                    nhrp_exts_length = 0;
                }
                else
                {
                    mand_part_len = extoff - sizeof(*fixed_hdr);
                    nhrp_exts_length = pktsz - extoff;
                }

                switch (op_type)
                {
                case NHRP_PKT_RESOLUTION_REQUEST:
                case NHRP_PKT_RESOLUTION_REPLY:
                case NHRP_PKT_REGISTRATION_REQUEST:
                case NHRP_PKT_REGISTRATION_REPLY:
                case NHRP_PKT_PURGE_REQUEST:
                case NHRP_PKT_PURGE_REPLY:

                    sp += sizeof(*fixed_hdr);
                    mand_hdr = (struct nhrp_mand_header *)sp;

                    shtl = GET_U_1(fixed_hdr->shtl);
                    sstl = GET_U_1(fixed_hdr->sstl);

                    spl = GET_U_1(mand_hdr->spl);
                    dpl = GET_U_1(mand_hdr->dpl);
                    // Skip to addresses
                    sp += sizeof(*mand_hdr); 
                    mand_part_len -= sizeof(*mand_hdr);

                    /* Source NBMA Address, if any. */
                    if (shtl != 0)
                    {
                        switch (afn)
                        {
                        case AFNUM_IP:
                            anon_ip4(sp);
                            break;
                        case AFNUM_IP6:
                            anon_ip6(sp);
                            break;
                        default:
                            break;
                        }
                        sp += shtl;
                        mand_part_len -= shtl;
                    }

                    /* Skip the Source NBMA SubAddress, if any */
                    if (sstl != 0)
                    {
                        sp += sstl;
                        mand_part_len -= sstl;
                    }

                    /* Source Protocol Address */
                    if (spl != 0)
                    {
                        switch (pro_type)
                        {
                        case ETHERTYPE_IP:
                            anon_ip4(sp);
                            break;
                        case ETHERTYPE_IPV6:
                            anon_ip6(sp);
                            break;
                        default:
                            break;
                        }
                        sp += spl;
                        mand_part_len -= spl;
                    }

                    /* Destination Protocol Address */
                    if (dpl != 0)
                    {
                        switch (pro_type)
                        {
                        case ETHERTYPE_IP:
                            anon_ip4(sp);
                            break;
                        case ETHERTYPE_IPV6:
                            anon_ip6(sp);
                            break;
                        default:
                            break;
                        }
                        sp += dpl;
                        mand_part_len -= dpl;
                    }

                    // Check if there are CIEs in mandatory part
                    /* Client Information Entries */
                    while (mand_part_len != 0)
                    {

                        cie = (struct nhrp_cie *)sp;
                        cie_len = 0;
                        cli_addr_tl = GET_U_1(cie->cli_addr_tl);
                        cli_saddr_tl = GET_U_1(cie->cli_saddr_tl);
                        cli_proto_tl = GET_U_1(cie->cli_proto_tl);

                        // Skip to the addresses
                        sp += sizeof(*cie);
                        cie_len += sizeof(*cie);
                        mand_part_len -= sizeof(*cie);

                        if (cli_addr_tl)
                        {
                            switch (afn)
                            {
                            case AFNUM_IP:
                                anon_ip4(sp);
                                break;
                            case AFNUM_IP6:
                                anon_ip6(sp);
                                break;

                            default:
                                break;
                            }
                            sp += cli_addr_tl;
                            cie_len += cli_addr_tl;
                            mand_part_len -= cli_addr_tl;
                        }

                        // Skip subaddress
                        if (cli_saddr_tl)
                        {
                            sp += cli_saddr_tl;
                            cie_len += cli_saddr_tl;
                            mand_part_len -= cli_saddr_tl;
                        }

                        if (cli_proto_tl)
                        {
                            switch (pro_type)
                            {
                            case ETHERTYPE_IP:
                                anon_ip4(sp);
                                break;
                            case ETHERTYPE_IPV6:
                                anon_ip6(sp);
                                break;
                            default:
                                break;
                            }
                            sp += cli_proto_tl;
                            cie_len += cli_proto_tl;
                            mand_part_len -= cli_proto_tl;
                        }
                    }
                    break;

                case NHRP_PKT_TRAFFIC_INDICATION:
                case NHRP_PKT_ERROR_INDICATION:
                    // Ignore the mandatory part and go to extensions
                    sp += sizeof(*fixed_hdr);
                    mand_hdr = (struct nhrp_mand_header *)sp;

                    shtl = GET_U_1(fixed_hdr->shtl);
                    sstl = GET_U_1(fixed_hdr->sstl);

                    spl = GET_U_1(mand_hdr->spl);
                    dpl = GET_U_1(mand_hdr->dpl);
                    sp += sizeof(*mand_hdr); // Skip to addresses
                    mand_part_len -= sizeof(*mand_hdr);

                    /* Source NBMA Address, if any. */
                    if (shtl != 0)
                    {
                        switch (afn)
                        {
                        case AFNUM_IP:

                            anon_ip4(sp);
                            break;
                        case AFNUM_IP6:
                            anon_ip6(sp);

                            break;
                        default:
                            break;
                        }
                        sp += shtl;
                        mand_part_len -= shtl;
                    }

                    /* Skip the Source NBMA SubAddress, if any */
                    if (sstl != 0)
                    {
                        sp += sstl;
                        mand_part_len -= sstl;
                    }

                    /* Source Protocol Address */
                    if (spl != 0)
                    {
                        switch (pro_type)
                        {
                        case ETHERTYPE_IP:

                            anon_ip4(sp);
                            break;
                        case ETHERTYPE_IPV6:
                            anon_ip6(sp);
                            break;
                        default:
                            break;
                        }
                        sp += spl;
                        mand_part_len -= spl;
                    }

                    /* Destination Protocol Address */
                    if (dpl != 0)
                    {
                        switch (pro_type)
                        {
                        case ETHERTYPE_IP:
                            anon_ip4(sp);
                            break;
                        case ETHERTYPE_IPV6:
                            anon_ip6(sp);
                            break;
                        default:
                            break;
                        }
                        sp += dpl;
                        mand_part_len -= dpl;
                    }

                    if (mand_part_len != 0)
                    {
                        // Skip the content in NHRP packet error
                        sp += mand_part_len;
                    }

                    break;

                default:
                    sp += extoff;
                    break;
                }

                // Check extensions
                while (nhrp_exts_length)
                {

                    u_short ext_type = GET_BE_U_2(sp);
                    sp += 2;
                    u_short ext_length = GET_BE_U_2(sp);
                    sp += 2;
                    nhrp_exts_length -= 4;
                    if (ext_length)
                    {
                        switch (ext_type)
                        {
                        case RESPONDER_ADDR_EXT:
                        case FORWARD_TRANSIT_EXT:
                        case REVERSE_TRANSIT_EXT:

                            cie = (struct nhrp_cie *)sp;
                            cie_len = 0;
                            cli_addr_tl = GET_U_1(cie->cli_addr_tl);
                            cli_saddr_tl = GET_U_1(cie->cli_saddr_tl);
                            cli_proto_tl = GET_U_1(cie->cli_proto_tl);

                            // Skip to the addresses
                            sp += sizeof(*cie);
                            cie_len += sizeof(*cie);

                            if (cli_addr_tl)
                            {
                                switch (afn)
                                {
                                case AFNUM_IP:
                                    anon_ip4(sp);
                                    break;
                                case AFNUM_IP6:
                                    anon_ip6(sp);
                                    break;

                                default:
                                    break;
                                }
                                sp += cli_addr_tl;
                                cie_len += cli_addr_tl;
                            }

                            // Skip subaddress
                            if (cli_saddr_tl)
                            {
                                sp += cli_saddr_tl;
                                cie_len += cli_saddr_tl;
                            }

                            if (cli_proto_tl)
                            {
                                switch (pro_type)
                                {
                                case ETHERTYPE_IP:
                                    anon_ip4(sp);
                                    break;
                                case ETHERTYPE_IPV6:
                                    anon_ip6(sp);
                                    break;
                                default:
                                    break;
                                }
                                sp += cli_proto_tl;
                                cie_len += cli_proto_tl;
                            }
                            nhrp_exts_length -= ext_length;
                            break;

                        case NHRP_AUTHENTICATION_EXT:

                            // Fetch the src addr
                            sp += 4;
                            switch (spl)
                            {

                            case 4:
                                anon_ip4(sp);
                                break;
                            case 16:
                                anon_ip6(sp);
                                break;
                            }

                            nhrp_exts_length -= ext_length;
                            sp += ext_length - 4;
                            break;

                        default:
                            nhrp_exts_length -= ext_length;
                            sp += ext_length;
                            break;
                        }
                    }
                }

                break;
            default:
                break;
            }
        }

        // If there is not GRE header, go to next layer.
        if (length_type == ETHERTYPE_IPV6 || length_type == ETHERTYPE_IP)
        {

            //Check IPv4 in IPv6
            if (nh == IPPROTO_IPV6)
            {
                ip6 = (struct ip6_hdr *)sp;
                anon_ip6(ip6->ip6_src);
                anon_ip6(ip6->ip6_dst);

                payload_len = GET_BE_U_2(ip6->ip6_plen);

                // Get Next Protocol
                nh = GET_U_1(ip6->ip6_nxt);
                sp += sizeof(struct ip6_hdr);
                // Look if there are extensions header and skip them
                skip_ip6_extensions(ndo, &sp, nh);
            }

            //Check IPv4 in IPv4
            else if (nh == IPPROTO_IPIP)
            {

                ip = (struct ip *)sp;
                anon_ip4(ip->ip_dst);
                anon_ip4(ip->ip_src);

                // If there is next header fetch it
                len = GET_BE_U_2(ip->ip_len);
                if (len > IP_HL(ip))
                {
                    // Get Protocol
                    nh = GET_U_1(ip->ip_p);
                    sp += IP_HL(ip) * 4;
                }
            }

            switch (nh)
            {

            case IPPROTO_ICMPV6:
                // Get the ICMP type
                dp = (struct icmp6_hdr *)sp;
                icmp6_type = GET_U_1(dp->icmp6_type);
                // Is_ndp is used to process ndp options after the switch
                int is_ndp = 0;
                int ndplen = 0;
                switch (icmp6_type)
                {

                case ND_NEIGHBOR_SOLICIT:
                    is_ndp = 1;
                    // Anonymize the target ip address
                    p = (struct nd_neighbor_solicit *)sp;
                    anon_ip6(p->nd_ns_target);

                    // Check for options
                    sp += sizeof(struct nd_neighbor_solicit);
                    ndplen = 24;
                    break;
                case ND_NEIGHBOR_ADVERT:
                    is_ndp = 1;
                    // Anonymize the target ip address
                    p2 = (struct nd_neighbor_advert *)sp;
                    anon_ip6(p2->nd_na_target);

                    // Check for options
                    sp += sizeof(struct nd_neighbor_advert);
                    ndplen = 24;
                    break;

                case ND_ROUTER_SOLICIT:
                    // Check for options
                    is_ndp = 1;
#define RTSOLLEN 8
                    sp += sizeof(struct nd_router_solicit);
                    break;
                case ND_ROUTER_ADVERT:
                    is_ndp = 1;
                    // Check for options
                    sp += sizeof(struct nd_router_advert);
                    ndplen = 16;
                    break;
                case ND_REDIRECT:
                    is_ndp = 1;
                    // Check for options
                    ndplen = 40;
                    sp += sizeof(struct nd_redirect);
                    break;

                case MLDV2_LISTENER_REPORT:
                    ngroups = GET_BE_U_2(dp->icmp6_data16[1]);
                    group = 8;
                    for (int i = 0; i < ngroups; i++)
                    {
                        anon_ip6(sp + group + 4);

                        nsrcs = GET_BE_U_2(sp + group + 2);

                        for (int j = 0; j < nsrcs; j++)
                        {
                            anon_ip6(sp + group + 20 + (j * sizeof(nd_ipv6)));
                        }
                        group += 20 + nsrcs * sizeof(nd_ipv6);
                    }
                    break;

                case MLD6_LISTENER_DONE:
                case MLD6_LISTENER_REPORT:
                case MLD6_LISTENER_QUERY:
                    mp = (struct mld6_hdr *)sp;
                    anon_ip6(mp->mld6_addr);
                    break;
                }
                // In NDP could be extensions
                if (is_ndp)
                {
                    while (payload_len > ndplen)
                    {
                        // There are options
                        op = (struct nd_opt_hdr *)sp;
                        opt_type = GET_U_1(op->nd_opt_type);
                        opt_len = GET_U_1(op->nd_opt_len);
                        if (opt_type == ND_OPT_PREFIX_INFORMATION)
                        {
                            opp = (struct nd_opt_prefix_info *)op;
                            // Get the prefix and anonymize it
                            anon_ip6(opp->nd_opt_pi_prefix);
                            payload_len -= opt_len << 3;
                        }
                        else if (opt_type == ND_OPT_RDNSS)
                        {
                            oprd = (struct nd_opt_rdnss *)op;
                            l = (opt_len - 1) / 2;
                            for (int i = 0; i < l; i++)
                            {
                                anon_ip6(oprd->nd_opt_rdnss_addr[i]);
                            }
                            payload_len -= opt_len << 3;
                        }
                        else
                        {
                            payload_len -= opt_len << 3;
                        }
                        sp += opt_len << 3;
                    }
                }
                break;

            case IPPROTO_TCP:

            case IPPROTO_UDP:

                up = (struct udphdr *)sp;
                sport = GET_BE_U_2(up->uh_sport);
                dport = GET_BE_U_2(up->uh_dport);
                ulen = GET_BE_U_2(up->uh_ulen);
                ulen -= sizeof(struct udphdr);

                if (ulen > 0)
                {
                    // u_char *cp;
                    sp = (u_char *)(up + 1);

                    // Check if the application layer is DNS
                    if (IS_SRC_OR_DST_PORT(NAMESERVER_PORT))
                    {

                        np = (dns_header_t *)sp;
                        flags = GET_BE_U_2(np->flags);
                        rcode = DNS_RCODE(flags);
                        qdcount = GET_BE_U_2(np->qdcount);
                        ancount = GET_BE_U_2(np->ancount);
                        nscount = GET_BE_U_2(np->nscount);
                        arcount = GET_BE_U_2(np->arcount);

                        // Anonymize if it is a response with no errors
                        if (DNS_QR(flags) && !DNS_RCODE(flags))
                        {
                            // Fetch the query section
                            sp = (u_char *)(np + 1);
                            // Skip the query section
                            for (int i = 0; i < qdcount; i++)
                            {

                                character = GET_U_1(sp);
                                // Skip name
                                while (character != 0)
                                {
                                    sp += 1;
                                    character = GET_U_1(sp);
                                }
                                sp += 1;
                                sp += 4; // Skipe type and class
                            }

                            for (int i = 0; i < ancount + nscount + arcount; i++)
                            {

                                character = GET_U_1(sp);

                                // If name is reserverd c0 go to Type
                                if ((character & TYPE_MASK) == TYPE_INDIR)
                                {
                                    sp += 2;
                                }
                                else
                                {
                                    while (character != 0 && ((character & TYPE_MASK) != TYPE_INDIR))
                                    {
                                        sp += 1;
                                        character = GET_U_1(sp);
                                    }
                                    if (character == 0)
                                        sp += 1;
                                    else if ((character & TYPE_MASK) == TYPE_INDIR)
                                        sp += 2;
                                }

                                // Type field: Only look for A and AAAA
                                typ = GET_BE_U_2(sp);
                                // Skip Type, Class and TTL
                                sp += 8;
                                length = GET_BE_U_2(sp);
                                // Skip length
                                sp += 2;
                                if (typ == T_A)
                                {
                                    if (length == 4)
                                    {
                                        // Fetch IPv4 Address
                                        anon_ip4(sp);
                                    }
                                }
                                else if (typ == T_AAAA)
                                {
                                    if (length == 16)
                                    {
                                        // Fetch IPv6 Address
                                        anon_ip6(sp);
                                    }
                                }
                                // Skip data
                                sp += length;
                            }
                        }
                    }
                    else if (IS_SRC_OR_DST_PORT(BOOTPS_PORT))
                    {
                        bp = (struct bootp *)sp;

                        anon_ip4(bp->bp_ciaddr);
                        anon_ip4(bp->bp_yiaddr);
                        anon_ip4(bp->bp_siaddr);
                        anon_ip4(bp->bp_giaddr);

                        bp_vendor = bp->bp_vend;
                        // Step over magic cookie
                        bp_vendor += sizeof(int32_t);
                        while (ND_TTEST_1(bp_vendor))
                        {
                            tag = GET_U_1(bp_vendor);
                            bp_vendor++;
                            if (tag == TAG_PAD || tag == TAG_END)
                                len = 0;
                            else
                            {
                                /* Get the length */
                                len = GET_U_1(bp_vendor);
                                bp_vendor++;
                            }

                            switch (tag)
                            {
                            case TAG_REQUESTED_IP:
                                anon_ip4(bp_vendor);

                            case TAG_SERVER_ID:
                                anon_ip4(bp_vendor);
                            }

                            /* Data left over? */
                            if (len)
                            {

                                bp_vendor += len;
                            }
                        }
                    }
                }
            }
        }
    }
}