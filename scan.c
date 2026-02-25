#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "global.h"
#include "log.h"

void hex(const unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

void scan(int fd, struct tpacket_req3 req, char *file) {
    FILE *fp = NULL;
    if (file != NULL) {
        fp = fopen(file, "wb");
        if (!fp) perror("fopen");
        setvbuf(fp, NULL, _IOFBF, 1 << 20);
        struct pcap_global_header gh = {
            .magic_number  = 0xa1b2c3d4,
            .version_major = 2,
            .version_minor = 4,
            .thiszone      = 0,
            .sigfigs       = 0,
            .snaplen       = 65535,
            .network       = 1
        };
        fwrite(&gh, sizeof(gh), 1, fp);
    }
    int ver = TPACKET_V3;
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver));
    setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    size_t ring_size = req.tp_block_nr * req.tp_block_size;
    uint8_t *rx_ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE,MAP_SHARED, fd, 0);
    if (rx_ring == MAP_FAILED)
    {
        perror("mmap");
        if (fp) fclose(fp);
        return;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int block_idx = 0;
    while (running)
    {
        struct tpacket_block_desc *block_hdr = (struct tpacket_block_desc *)(rx_ring + block_idx * req.tp_block_size);
        while (!(block_hdr->hdr.bh1.block_status & TP_STATUS_USER)) {
            poll(&pfd, 1, -1);
        }
        int num_pkts = block_hdr->hdr.bh1.num_pkts;
        struct tpacket3_hdr *pkt_hdr = (struct tpacket3_hdr *)((uint8_t *)block_hdr + block_hdr->hdr.bh1.offset_to_first_pkt);
        for (int i = 0; i < num_pkts; i++)
        {
            unsigned char *data = (unsigned char *)pkt_hdr + pkt_hdr->tp_mac;
            struct ethhdr *eth = (struct ethhdr *)data;
            if (ntohs(eth->h_proto) == ETH_P_IP) {
                struct iphdr *ip = (struct iphdr *)((uint8_t *)pkt_hdr + pkt_hdr->tp_net);
                char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ip->saddr, src, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &ip->daddr, dst, INET_ADDRSTRLEN);
                printf("[IP Packet]\n");
                printf("Source IP: %s \nDst IP: %s\n", src, dst);
                printf("Packet Length: %u bytes\n", pkt_hdr->tp_snaplen);
                time_t ts = pkt_hdr->tp_sec;
                char time_str[64];
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&ts));
                printf("Timestamp: %s\n", time_str);
                printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       eth->h_source[0], eth->h_source[1], eth->h_source[2],
                       eth->h_source[3], eth->h_source[4], eth->h_source[5]);
                printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                       eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
                printf("TTL: %d\n" , ip->ttl);
                const char *protocol;
                switch(ip->protocol)
                {
                    case 6:  protocol = "TCP"; break;
                    case 17: protocol = "UDP"; break;
                    case 1:  protocol = "ICMP"; break;
                    case 58: protocol = "IPv6 ICMP"; break;
                    default: protocol = "Unknown"; break;
                }
                printf("Protocol: %s\n", protocol);
                if (ip->protocol == IPPROTO_TCP)
                {
                    struct tcphdr *tcph = (struct tcphdr *)((uint8_t *)ip + ip->ihl * 4);
                    printf("Source Port: %u\n" , ntohs(tcph->source));
                    printf("Destination Port: %u\n" , ntohs(tcph->dest));
                    if (tcph->syn) printf("TCP Flag: SYN\n");
                    else if (tcph->ack)
                    {
                        printf("TCP Flag: ACK");
                        printf("ACK SEQ: %d" , tcph->ack_seq);
                    }
                    else if (tcph->fin) printf("TCP Flag: FIN\n"); 
                    else if (tcph->rst) printf("TCP Flag: RST \n");
                    else if (tcph->psh) printf("TCP Flag: PSH\n");
                    else if (tcph->urg) printf("TCP Flag: URG \n");
                    printf("Sequence: %d\n" , tcph->seq);
                }
                else if (ip->protocol == IPPROTO_UDP)
                {
                    struct udphdr *udph = (struct udphdr *)((uint8_t *)ip + ip->ihl * 4);
                    printf("Source Port: %d\n" , ntohs(udph->source));
                    printf("Destination Port: %d\n" , udph->dest);
                }
            } else
            {
                const char *protocol;
                switch (ntohs(eth->h_proto))
                {
                    case 0x0806: protocol = "ARP"; break;
                    case 0x0842: protocol = "Wake-on-LAN"; break;
                    case 0x8100: protocol = "VLAN"; break;
                    default: protocol = "Unknown"; break;
                }
                printf("[Non-IP Packet] Protocol: %s  Length: %u bytes\n",
                       protocol, pkt_hdr->tp_snaplen);
            }
            printf("Payload:\n");
            hex(data, pkt_hdr->tp_snaplen);
            if (fp)
            {
                struct pcap_packet_header ph;
                ph.ts_sec  = pkt_hdr->tp_sec;
                ph.ts_usec = pkt_hdr->tp_nsec / 1000;
                ph.incl_len = pkt_hdr->tp_snaplen;
                ph.orig_len = pkt_hdr->tp_len;
                fwrite(&ph, sizeof(ph), 1, fp);
                fwrite(data, pkt_hdr->tp_snaplen, 1, fp);
            }
            pkt_hdr = (struct tpacket3_hdr *)((uint8_t *)pkt_hdr + pkt_hdr->tp_next_offset);
        }
        block_hdr->hdr.bh1.block_status = TP_STATUS_KERNEL;
        block_idx = (block_idx + 1) % req.tp_block_nr;
    }
    munmap(rx_ring, ring_size);
    if (fp) fclose(fp);
}
