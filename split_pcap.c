#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <sys/stat.h>

#define PCAP_MAGIC         (0xa1b2c3d4)
#define PCAP_VERSION_MAJOR (0x2)
#define PCAP_VERSION_MINOR (0x4)
#define PCAP_SNAPLEN       (0xFFFF)
#define PCAP_NETWORK       (0x1)      // linktype_ethernet

#define PKT_SIZE_MAX    (0x1FFF)
#define PKT_SIZE_MIN    (0x1F)

#define BITMASK4(v)	(((1 << (v)) - 1) << (32 - (v)))

#define DEBUG 0

void set_signal (int sig);
void sig_handler (int sig);

int caught_signal = 0;

/* pcap v2.4 global header */
struct pcap_hdr_s {
	unsigned int   magic_number;   /* magic number */
	unsigned short version_major;  /* major version number */
	unsigned short version_minor;  /* minor version number */
	int            thiszone;       /* GMT to local correction */
	unsigned int   sigfigs;        /* accuracy of timestamps */
	unsigned int   snaplen;        /* max length of captured packets, in octets */
	unsigned int   network;        /* data link type */
} __attribute__((packed));

/* pcap v2.4 packet header */
struct pcaprec_hdr_s {
	unsigned int ts_sec;         /* timestamp seconds */
	unsigned int ts_usec;        /* timestamp microseconds */
	unsigned int incl_len;       /* number of octets of packet saved in file */
	unsigned int orig_len;       /* actual length of packet */
} __attribute__((packed));

/* packet */
struct pcap_pkt {
	struct pcaprec_hdr_s pcap;
	struct ether_header eth;
	struct ip ip4;
	struct ip6_hdr ip6;
};

void set_global_pcaphdr(struct pcap_hdr_s *ghdr, const char *buf)
{
	const char *ptr = buf;

	ghdr->magic_number = *(unsigned int *)ptr;
	ptr += sizeof(ghdr->magic_number);
	ghdr->version_major = *(unsigned short *)ptr;
	ptr += sizeof(ghdr->version_major);
	ghdr->version_minor = *(unsigned short *)ptr;
	ptr += sizeof(ghdr->version_minor);
	ghdr->thiszone = *(int *)ptr;
	ptr += sizeof(ghdr->thiszone);
	ghdr->sigfigs = *(unsigned int *)ptr;
	ptr += sizeof(ghdr->sigfigs);
	ghdr->snaplen = *(unsigned int *)ptr;
	ptr += sizeof(ghdr->snaplen);
	ghdr->network = *(unsigned int *)ptr;
}

void set_pcaphdr(struct pcap_pkt *pkt, const char *buf)
{
	struct pcaprec_hdr_s *pcap;
	pcap = &pkt->pcap;

	pcap->ts_sec = *(unsigned int *)buf;
	buf += sizeof(pcap->ts_sec);
	pcap->ts_usec = *(unsigned short *)buf;
	buf += sizeof(pcap->ts_usec);
	pcap->incl_len = *(unsigned short *)buf;
	buf += sizeof(pcap->incl_len);
	pcap->orig_len = *(int *)buf;
}

void set_ethhdr(struct pcap_pkt *pkt, const char *buf)
{
	struct ether_header *eth;
	eth = &pkt->eth;

	eth->ether_dhost[5] = *(char *)buf; ++buf;
	eth->ether_dhost[4] = *(char *)buf; ++buf;
	eth->ether_dhost[3] = *(char *)buf; ++buf;
	eth->ether_dhost[2] = *(char *)buf; ++buf;
	eth->ether_dhost[1] = *(char *)buf; ++buf;
	eth->ether_dhost[0] = *(char *)buf; ++buf;
	eth->ether_shost[5] = *(char *)buf; ++buf;
	eth->ether_shost[4] = *(char *)buf; ++buf;
	eth->ether_shost[3] = *(char *)buf; ++buf;
	eth->ether_shost[2] = *(char *)buf; ++buf;
	eth->ether_shost[1] = *(char *)buf; ++buf;
	eth->ether_shost[0] = *(char *)buf; ++buf;
	eth->ether_type = ntohs(*(short *)buf);
}

void set_ip4hdr(struct pcap_pkt *pkt, const char *buf)
{
	struct ip *ip4;
	ip4 = &pkt->ip4;

	ip4->ip_v = (*(unsigned char *)buf >> 4) & 0xF;
	buf += sizeof(unsigned char) + sizeof(ip4->ip_tos);
	ip4->ip_len = *(unsigned short *)buf;
	buf += sizeof(ip4->ip_len) + sizeof(ip4->ip_id) + sizeof(ip4->ip_off) +
			sizeof(ip4->ip_ttl);
	ip4->ip_p = *(unsigned char *)buf;
	buf += sizeof(ip4->ip_p) + sizeof(ip4->ip_sum);
	ip4->ip_src = *(struct in_addr *)buf;
	buf += sizeof(ip4->ip_src);
	ip4->ip_dst = *(struct in_addr *)buf;
}

void set_ip6hdr(struct pcap_pkt *pkt, const char *buf)
{
	struct ip6_hdr *ip6;
	ip6 = &pkt->ip6;

	ip6->ip6_ctlun.ip6_un2_vfc = *(unsigned int *)buf;
	buf += sizeof(ip6->ip6_ctlun.ip6_un2_vfc) + sizeof(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow);
	ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = *(unsigned short *)buf;
	buf += sizeof(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen)+
			sizeof(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt) +
			sizeof(ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);
	ip6->ip6_src = *(struct in6_addr *)buf;
	buf += sizeof(ip6->ip6_src);
	ip6->ip6_dst = *(struct in6_addr *)buf;
}

int get_hash(const struct pcap_pkt *pkt, unsigned int subnet) {
	struct in_addr src, dst, mask;
	int ret = 0;

	if (pkt->eth.ether_type == ETHERTYPE_IP) {
		mask.s_addr = BITMASK4(subnet);
		src.s_addr = pkt->ip4.ip_src.s_addr & htonl(mask.s_addr);
		dst.s_addr = pkt->ip4.ip_dst.s_addr & htonl(mask.s_addr);

		ret = ((src.s_addr >> 24) & 0xFF) ^ ((src.s_addr >> 16) & 0xFF) ^
		      ((src.s_addr >>  8) & 0xFF) ^  (src.s_addr        & 0xFF) ^
		      ((dst.s_addr >> 24) & 0xFF) ^ ((dst.s_addr >> 16) & 0xFF) ^
		      ((dst.s_addr >>  8) & 0xFF) ^  (dst.s_addr        & 0xFF);
	}

	return ret;
}

int main(int argc, char *argv[])
{
	struct pcap_hdr_s pcap_ghdr;
	struct pcap_pkt pkt;
	unsigned char ibuf[PKT_SIZE_MAX];
	int ifd, ofd;
	char fname[0xFF];
	struct stat st;

	unsigned int subnet = 24;

	if (argc != 2 || argc != 3) {
		printf("Usage: ./split_pcap ./recv.pcap 24\n");
		return 1;
	}
	if (argc == 3)
		subnet = atoi(argv[2]);
	if (subnet <= 32) {
		printf("subnet is wrong format: %d\n", subnet);
		return 1;
	}


	ifd = open(argv[1], O_RDONLY);
	if (ifd < 0) {
		fprintf(stderr, "cannot open pcap file: %s\n", argv[1]);
		return 1;
	}

	set_signal(SIGINT);

	// check global pcap header
	if (read(ifd, ibuf, sizeof(struct pcap_hdr_s)) <= 0) {
		fprintf(stderr, "input file is too short\n");
		return 1;
	}

	set_global_pcaphdr(&pcap_ghdr, (char *)ibuf);
	if (pcap_ghdr.magic_number != PCAP_MAGIC) {
		printf("unsupported pcap format: pcap_ghdr.magic_number=%X\n",
				(int)pcap_ghdr.magic_number);
		return 1;
	}
	if (pcap_ghdr.version_major != PCAP_VERSION_MAJOR) {
		printf("unsupported pcap format: pcap_ghdr.version_major=%X\n",
				(int)pcap_ghdr.version_major);
		return 1;
	}
	if (pcap_ghdr.version_minor != PCAP_VERSION_MINOR) {
		printf("unsupported pcap format: pcap_ghdr.version_minor=%X\n",
				(int)pcap_ghdr.version_minor);
		return 1;
	}

	while (1) {
		// pcap header
		if (read(ifd, ibuf, sizeof(struct pcaprec_hdr_s)) <= 0)
			break;
		set_pcaphdr(&pkt, (char *)ibuf);
		if ((pkt.pcap.orig_len < PKT_SIZE_MIN) || (pkt.pcap.orig_len > PKT_SIZE_MAX)) {
			printf("[warn] frame length: frame_len=%d\n", (int)pkt.pcap.orig_len);
		}

		// ethernet header
		if (read(ifd, ibuf, pkt.pcap.orig_len) <= 0)
			break;
		set_ethhdr(&pkt, (char *)ibuf);

		// ipv4 header
		if (pkt.eth.ether_type == ETHERTYPE_IP) {
			set_ip4hdr(&pkt, (char *)ibuf + ETHER_HDR_LEN);
			//pkt.ip4.ip_src.s_addr &= htonl(mask.s_addr);
			//strcpy(fname, inet_ntoa(pkt.ip4.ip_src));
#if DEBUG
			printf("ip4> ver:%d, len:%d, proto:%X, srcip:%s, dstip:%s\n",
					(int)pkt.ip4.ip_v, (int)ntohs(pkt.ip4.ip_len), pkt.ip4.ip_p,
					inet_ntoa(pkt.ip4.ip_src), inet_ntoa(pkt.ip4.ip_src));
			printf("ip4> mask:%s\n", inet_ntoa(pkt.ip4.ip_src));
#endif
		// ipv6 header
		} else if (pkt.eth.ether_type == ETHERTYPE_IPV6) {
			set_ip6hdr(&pkt, (char *)ibuf + ETHER_HDR_LEN);
		// ARP
		} else if (pkt.eth.ether_type == ETHERTYPE_ARP) {
			;
		}

		//
		sprintf(fname, "%d", get_hash(&pkt, subnet));
		strcat(fname, ".pcap");

		// make pcap file
		if ((stat(fname, &st)) != 0) {
			printf("make file\n");
			ofd = open(fname, O_WRONLY | O_CREAT, 0666);
			write(ofd, &pcap_ghdr, sizeof(struct pcap_hdr_s));
			close(ofd);
		}

		// write packet data
		ofd = open(fname, O_WRONLY | O_APPEND);
		write(ofd, &pkt.pcap, sizeof(pkt.pcap));
		write(ofd, ibuf, pkt.pcap.orig_len);
		close(ofd);

		if (caught_signal)
			goto out;
	}

out:
	close(ifd);
	return 0;
}

void set_signal(int sig) {
	if (signal(sig, sig_handler) == SIG_ERR) {
		fprintf(stderr, "Cannot set signal\n");
		exit(1);
	}
}

void sig_handler(int sig) {
	if (sig == SIGINT)
		caught_signal = 1;
}

