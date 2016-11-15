#include <QCoreApplication>

#define  WPCAP
#define  HAVE_REMOTE
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #include <winsock.h>
#endif


void usage();

void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);


int main(int argc, char *argv[])
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct timeval st_ts;
    u_int netmask;
    struct bpf_program fcode;

    /* Check the validity of the command line */
    if (argc != 2)
    {
        usage();
        return -1;
    }

    /* Open the output adapter */
    if ( (fp= pcap_open_live(argv[1], 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open adapter %s.\n", errbuf);
        return -1;
    }

    /* Don't care about netmask, it won't be used for this filter */
    netmask=0xffffff;

    //compile the filter
    if (pcap_compile(fp, &fcode, "tcp", 1, netmask) <0 )
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        return -1;
    }

    //set the filter
    if (pcap_setfilter(fp, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        pcap_close(fp);
        /* Free the device list */
        return -1;
    }

    // pcap_setmode() is only used for Windows.

    printf("TCP traffic summary:\n");

    /* Start the main loop */
    pcap_loop(fp, 0, dispatcher_handler, (unsigned char *)&st_ts);

    pcap_close(fp);

    QCoreApplication a(argc, argv);

    return a.exec();
}

void dispatcher_handler(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct timeval *old_ts = (struct timeval *)state;
    typedef union _LARGE_INTEGER {
        struct {
            unsigned long LowPart;
            long HighPart;
        } DUMMYSTRUCTNAME;
        struct {
            unsigned long LowPart;
            long HighPart;
        } u;
        long long QuadPart;
    } LARGE_INTEGER;

    u_int delay;
    LARGE_INTEGER Bps,Pps;
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;

    /* Calculate the delay in microseconds from the last sample. */
    /* This value is obtained from the timestamp that the associated with the sample. */
    delay=(header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;
    /* Get the number of Bits per second */
    Bps.QuadPart=(((*(long long*)(pkt_data + 8)) * 8 * 1000000) / (delay));
    /*                                            ^      ^
                                                  |      |
                                                  |      |
                                                  |      |
                         converts bytes in bits --       |
                                                         |
                    delay is expressed in microseconds --
    */

    /* Get the number of Packets per second */
    Pps.QuadPart=(((*(long long*)(pkt_data)) * 1000000) / (delay));

    /* Convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime = *localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

    /* Print timestamp*/
    printf("%s ", timestr);

    /* Print the samples */
    printf("BPS=%I64u ", Bps.QuadPart);
    printf("PPS=%I64u\n", Pps.QuadPart);

    //store current timestamp
    old_ts->tv_sec=header->ts.tv_sec;
    old_ts->tv_usec=header->ts.tv_usec;
}


void usage()
{

    printf("\nShows the TCP traffic load, in bits per second and packets per second.\nCopyright (C) 2002 Loris Degioanni.\n");
    printf("\nUsage:\n");
    printf("\t tcptop adapter\n");
    printf("\t You can use \"WinDump -D\" if you don't know the name of your adapters.\n");

    exit(0);
}

