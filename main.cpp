#include <stdio.h>
#include <pcap.h>

#include <netinet/in.h>
#include "config.h"
#include "libnet-macros.h"
#include "libnet-headers.h"

#include <string>
#include <string.h>

using namespace std;

int main(int argc, char *argv[])
{
    if (argc != 2 ) {
        printf("pcaptest2 <interface>\n");
        return(0);
    }

    char *dev = argv[1];
    printf("Device: %s\n", dev);

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;          /* The compiled filter expression */
    char filter_exp[] = "tcp port 80";     /* The filter expression */
    bpf_u_int32 mask;               /* The netmask of our sniffing device */
    bpf_u_int32 net;                /* The IP of our sniffing device */
    struct pcap_pkthdr header;      /* The header that pcap gives us */
    const u_char *packet;           /* The actual packet */

    string searchlist = "http://";
    uint numKeywords = searchlist.size();

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    while(true) {
        /* Grab a packet */
        packet = pcap_next(handle, &header);
        if (packet == NULL) continue;

        libnet_ethernet_hdr* eth_hdr = (libnet_ethernet_hdr*) packet;
        if ( ntohs(eth_hdr->ether_type) != ETHERTYPE_IP /* 0x0800 */ )
            continue;

        libnet_ipv4_hdr* ip_hdr = (libnet_ipv4_hdr*) ((char*)eth_hdr + 14 /* Ethernet MAC header size */);
        if ( ip_hdr->ip_p != 6 /* tcp */)
            continue;

        libnet_tcp_hdr* tcp_hdr = (libnet_tcp_hdr*) ((char*)ip_hdr + (ip_hdr->ip_hl * 4));
        u_int16_t sport = ntohs(tcp_hdr->th_sport);
        u_int16_t dport = ntohs(tcp_hdr->th_dport);

        /* Print Port number*/
        //        printf("%u->%u\n", sport, dport);

        /* Print its length */
        //        printf("Jacked packet length : [%d]", header.len);

        u_int16_t tcp_seg_len = ntohs(ip_hdr->ip_len) - (u_int16_t)(ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4);

        /* Print tcp segment's length */
        //        printf("\n IP Header Total length : [%d], Fragmented : [%d]", ntohs(ip_hdr->ip_len), ip_hdr->ip_off);
        //        printf("\n IP Header length : [%d]", ip_hdr->ip_hl*4);
        //        printf("\n TCP Header length : [%d]", tcp_hdr->th_off*4);
        //        printf("\n Tcp segment's length : [%d]\n", tcp_seg_len);

        if (tcp_seg_len > 0) {
            char* tcp_segment = (char*)((char*)tcp_hdr + tcp_hdr->th_off * 4);

            /* Print TCP segment */
//            printf("%s\n", tcp_segment);

            /* Find search Keywords */
            string buffer = string(tcp_segment);
            char* url;
            for (int i=0; i<1; i++) {
                size_t found = buffer.find(searchlist);
                uint sPos, ePos, ePos1, ePos2, ePos3, length;
                sPos = ePos = ePos1 = ePos2 = ePos3 = 999;
                //                printf("%d %d %d %d %d", sPos, ePos, ePos1, ePos2, ePos3);
                if (found!=string::npos) {
                    sPos = found;
                    ePos1 = buffer.find_first_of(';',sPos+1);
                    ePos2 = buffer.find_first_of('"',sPos+1);
                    ePos3 = buffer.find_first_of('\0',sPos+1);
                    if ((ePos1 < ePos2) && (ePos1 < ePos3)) { ePos = ePos1; } else {}
                    if ((ePos2 < ePos1) && (ePos2 < ePos3)) { ePos = ePos2; } else {}
                    if ((ePos3 < ePos1) && (ePos3 < ePos2)) { ePos = ePos3; } else {}
//                    printf("\n%d %d %d %d %d", sPos, ePos, ePos1, ePos2, ePos3);

                    if ( sPos < 999 && ePos < 999 && ePos > sPos ) {
                        printf("[%d]  start : [%d], end : [%d] \n", i, sPos, ePos);
                        length = ePos - sPos;
                        url = (char*)malloc(sizeof(char*)*length);
                        memset(url, '\0', sizeof(char)*length);
                        buffer.copy(url, length, sPos);
                        printf("%s\n", url);
                    }
                }
            }
        }
    }

    /* And close the session */
    pcap_close(handle);
    return(0);
}
