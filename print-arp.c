#include <arp.h>

static int
isnonzero(netdissect_options *ndo, const u_char *a, size_t len)
{
	while (len != 0) {
		if (GET_U_1(a) != 0)
			return (1);
		a++;
		len--;
	}
	return (0);
}

static void
tpaddr_print_ip(netdissect_options *ndo,
	        const struct arp_pkthdr *ap, u_short pro)
{
	if (pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL)
		ND_PRINT("<wrong proto type>");
	else if (PROTO_LEN(ap) != 4)
		ND_PRINT("<wrong len>");
	else
		ND_PRINT("%s", GET_IPADDR_STRING(TPA(ap)));
}

static void
spaddr_print_ip(netdissect_options *ndo,
	        const struct arp_pkthdr *ap, u_short pro)
{
	if (pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL)
		ND_PRINT("<wrong proto type>");
	else if (PROTO_LEN(ap) != 4)
		ND_PRINT("<wrong len>");
	else
		ND_PRINT("%s", GET_IPADDR_STRING(SPA(ap)));
}

static void
atmarp_addr_print(netdissect_options *ndo,
		  const u_char *ha, u_int ha_len, const u_char *srca,
    u_int srca_len)
{
	if (ha_len == 0)
		ND_PRINT("<No address>");
	else {
		ND_PRINT("%s", GET_LINKADDR_STRING(ha, LINKADDR_ATM, ha_len));
		if (srca_len != 0)
			ND_PRINT(",%s",
				  GET_LINKADDR_STRING(srca, LINKADDR_ATM, srca_len));
	}
}

static void
atmarp_tpaddr_print(netdissect_options *ndo,
		    const struct atmarp_pkthdr *ap, u_short pro)
{
	if (pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL)
		ND_PRINT("<wrong proto type>");
	else if (ATMTPROTO_LEN(ap) != 4)
		ND_PRINT("<wrong tplen>");
	else
		ND_PRINT("%s", GET_IPADDR_STRING(ATMTPA(ap)));
}

static void
atmarp_spaddr_print(netdissect_options *ndo,
		    const struct atmarp_pkthdr *ap, u_short pro)
{
	if (pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL)
		ND_PRINT("<wrong proto type>");
	else if (ATMSPROTO_LEN(ap) != 4)
		ND_PRINT("<wrong splen>");
	else
		ND_PRINT("%s", GET_IPADDR_STRING(ATMSPA(ap)));
}

static void
atmarp_print(netdissect_options *ndo,
	     const u_char *bp, u_int length, u_int caplen)
{
	const struct atmarp_pkthdr *ap;
	u_short pro, hrd, op;

	ap = (const struct atmarp_pkthdr *)bp;
	ND_TCHECK_SIZE(ap);

	hrd = ATMHRD(ap);
	pro = ATMPRO(ap);
	op = ATMOP(ap);

	ND_TCHECK_LEN(ATMTPA(ap), ATMTPROTO_LEN(ap));

        if (!ndo->ndo_eflag) {
            ND_PRINT("ARP, ");
        }

	if ((pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL) ||
	    ATMSPROTO_LEN(ap) != 4 ||
            ATMTPROTO_LEN(ap) != 4 ||
            ndo->ndo_vflag) {
                ND_PRINT("%s, %s (len %u/%u)",
                          tok2str(arphrd_values, "Unknown Hardware (%u)", hrd),
                          tok2str(ethertype_values, "Unknown Protocol (0x%04x)", pro),
                          ATMSPROTO_LEN(ap),
                          ATMTPROTO_LEN(ap));

                /* don't know about the address formats */
                if (!ndo->ndo_vflag) {
                    goto out;
                }
	}

        /* print operation */
        ND_PRINT("%s%s ",
               ndo->ndo_vflag ? ", " : "",
               tok2str(arpop_values, "Unknown (%u)", op));

	switch (op) {

	case ARPOP_REQUEST:
		ND_PRINT("who-has ");
		atmarp_tpaddr_print(ndo, ap, pro);
		if (ATMTHRD_LEN(ap) != 0) {
			ND_PRINT(" (");
			atmarp_addr_print(ndo, ATMTHA(ap), ATMTHRD_LEN(ap),
			    ATMTSA(ap), ATMTSLN(ap));
			ND_PRINT(")");
		}
		ND_PRINT(" tell ");
		atmarp_spaddr_print(ndo, ap, pro);
		break;

	case ARPOP_REPLY:
		atmarp_spaddr_print(ndo, ap, pro);
		ND_PRINT(" is-at ");
		atmarp_addr_print(ndo, ATMSHA(ap), ATMSHRD_LEN(ap), ATMSSA(ap),
                                  ATMSSLN(ap));
		break;

	case ARPOP_INVREQUEST:
		ND_PRINT("who-is ");
		atmarp_addr_print(ndo, ATMTHA(ap), ATMTHRD_LEN(ap), ATMTSA(ap),
		    ATMTSLN(ap));
		ND_PRINT(" tell ");
		atmarp_addr_print(ndo, ATMSHA(ap), ATMSHRD_LEN(ap), ATMSSA(ap),
		    ATMSSLN(ap));
		break;

	case ARPOP_INVREPLY:
		atmarp_addr_print(ndo, ATMSHA(ap), ATMSHRD_LEN(ap), ATMSSA(ap),
		    ATMSSLN(ap));
		ND_PRINT("at ");
		atmarp_spaddr_print(ndo, ap, pro);
		break;

	case ARPOP_NAK:
		ND_PRINT("for ");
		atmarp_spaddr_print(ndo, ap, pro);
		break;

	default:
		ND_DEFAULTPRINT((const u_char *)ap, caplen);
		return;
	}

 out:
        ND_PRINT(", length %u", length);
}

void
arp_print(netdissect_options *ndo,
	  const u_char *bp, u_int length, u_int caplen)
{
	const struct arp_pkthdr *ap;
	u_short pro, hrd, op, linkaddr;

	ndo->ndo_protocol = "arp";
	ap = (const struct arp_pkthdr *)bp;
	ND_TCHECK_SIZE(ap);

	hrd = HRD(ap);
	pro = PRO(ap);
	op = OP(ap);


        /* if its ATM then call the ATM ARP printer
           for Frame-relay ARP most of the fields
           are similar to Ethernet so overload the Ethernet Printer
           and set the linkaddr type for GET_LINKADDR_STRING() accordingly */

        switch(hrd) {
        case ARPHRD_ATM2225:
            atmarp_print(ndo, bp, length, caplen);
            return;
        case ARPHRD_FRELAY:
            linkaddr = LINKADDR_FRELAY;
            break;
        default:
            linkaddr = LINKADDR_MAC48;
            break;
	}

	ND_TCHECK_LEN(TPA(ap), PROTO_LEN(ap));

        if (!ndo->ndo_eflag) {
            ND_PRINT("ARP, ");
        }

        /* print hardware type/len and proto type/len */
        if ((pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL) ||
	    PROTO_LEN(ap) != 4 ||
            HRD_LEN(ap) == 0 ||
            ndo->ndo_vflag) {
            ND_PRINT("%s (len %u), %s (len %u)",
                      tok2str(arphrd_values, "Unknown Hardware (%u)", hrd),
                      HRD_LEN(ap),
                      tok2str(ethertype_values, "Unknown Protocol (0x%04x)", pro),
                      PROTO_LEN(ap));

            /* don't know about the address formats */
            if (!ndo->ndo_vflag) {
                goto out;
            }
	}

        /* print operation */
        ND_PRINT("%s%s ",
               ndo->ndo_vflag ? ", " : "",
               tok2str(arpop_values, "Unknown (%u)", op));

	switch (op) {

	case ARPOP_REQUEST:
		ND_PRINT("who-has ");
		tpaddr_print_ip(ndo, ap, pro);
		if (isnonzero(ndo, (const u_char *)THA(ap), HRD_LEN(ap)))
			ND_PRINT(" (%s)",
				  GET_LINKADDR_STRING(THA(ap), linkaddr, HRD_LEN(ap)));
		ND_PRINT(" tell ");
		spaddr_print_ip(ndo, ap, pro);
		break;

	case ARPOP_REPLY:
		spaddr_print_ip(ndo, ap, pro);
		ND_PRINT(" is-at %s",
                          GET_LINKADDR_STRING(SHA(ap), linkaddr, HRD_LEN(ap)));
		break;

	case ARPOP_REVREQUEST:
		/*
		 * XXX - GET_LINKADDR_STRING() may return a pointer to
		 * a static buffer, so we only have one call to it per
		 * ND_PRINT() call.
		 *
		 * This should be done in a cleaner fashion.
		 */
		ND_PRINT("who-is %s",
			  GET_LINKADDR_STRING(THA(ap), linkaddr, HRD_LEN(ap)));
		ND_PRINT(" tell %s",
			  GET_LINKADDR_STRING(SHA(ap), linkaddr, HRD_LEN(ap)));
		break;

	case ARPOP_REVREPLY:
		ND_PRINT("%s at ",
			  GET_LINKADDR_STRING(THA(ap), linkaddr, HRD_LEN(ap)));
		tpaddr_print_ip(ndo, ap, pro);
		break;

	case ARPOP_INVREQUEST:
		/*
		 * XXX - GET_LINKADDR_STRING() may return a pointer to
		 * a static buffer, so we only have one call to it per
		 * ND_PRINT() call.
		 *
		 * This should be done in a cleaner fashion.
		 */
		ND_PRINT("who-is %s",
			  GET_LINKADDR_STRING(THA(ap), linkaddr, HRD_LEN(ap)));
		ND_PRINT(" tell %s",
			  GET_LINKADDR_STRING(SHA(ap), linkaddr, HRD_LEN(ap)));
		break;

	case ARPOP_INVREPLY:
		ND_PRINT("%s at ",
			  GET_LINKADDR_STRING(SHA(ap), linkaddr, HRD_LEN(ap)));
		spaddr_print_ip(ndo, ap, pro);
		break;

	default:
		ND_DEFAULTPRINT((const u_char *)ap, caplen);
		return;
	}

 out:
        ND_PRINT(", length %u", length);
}
