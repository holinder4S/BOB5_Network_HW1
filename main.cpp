#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <libnet.h>

#define PROMISCOUS 1
#define NONPROMISCUOUS 0

// IP 헤더 구조체
struct ip *iph;
// TCP 헤더 구조체
struct tcphdr *tcph;

char *get_protocol_str(u_int8_t protocol) {
    char* protocol_type_str;

    switch(protocol) {
    case IPPROTO_ICMP:
        protocol_type_str = "ICMP";
        break;
    case IPPROTO_IGMP:
        protocol_type_str = "IGMP";
        break;
    case IPPROTO_TCP:
        protocol_type_str = "TCP";
        break;
    case IPPROTO_UDP:
        protocol_type_str = "UDP";
        break;
    default:
        protocol_type_str = "UNKNOWN";
        break;
    }

    return protocol_type_str;
}

char *get_tcp_flag_str(u_int8_t tcp_flags) {
    char *flags[9] = {"FIN","SYN","RST","PUSH","ACK","URG","ECE","CWR"};
    int flag_no[8] = {0,};
    static char tcp_flags_str[64]="";
    char tmp[10]="";
    int len;

    if(tcp_flags & TH_FIN) flag_no[0] = 1;
    if(tcp_flags & TH_SYN) flag_no[1] = 1;
    if(tcp_flags & TH_RST) flag_no[2] = 1;
    if(tcp_flags & TH_PUSH) flag_no[3] = 1;
    if(tcp_flags & TH_ACK) flag_no[4] = 1;
    if(tcp_flags & TH_URG) flag_no[5] = 1;
    if(tcp_flags & TH_ECE) flag_no[6] = 1;
    if(tcp_flags & TH_CWR) flag_no[7] = 1;

    tcp_flags_str[0] = '\0';
    for(int i=0; i<8; i++) {
        tmp[0] = '\0';
        if(flag_no[i] == 1) {
            strcat(tmp, flags[i]);
            strcat(tmp, " | ");
            strcat(tcp_flags_str, tmp);
        }
    }

    len = strlen(tcp_flags_str);
    tcp_flags_str[len-3] = '\0';
    return tcp_flags_str;
}

void print_data(const u_char *packet, int len) {
    unsigned int i, j;
    int chcnt = 0;

    for(i=0; i<len+((len % 16) ? (16 - len % 16) : 0); i++) {
        if(i % 16 == 0) printf("       0x%04x: ", i);
        if(i < len) printf("%02x ", 0xFF & ((char*)packet)[i]);
        else printf("   ");

        if(i % 16 == (16 - 1)) {
            for(j=i-(16 - 1); j <= i; j++) {
                if(j>=len) putchar(' ');
                else if(isprint(((char*)packet)[j])) putchar(0xFF & ((char*)packet)[j]);
                else putchar('.');
            }
            putchar('\n');
        }
    }
    /*
    printf("       ");
    while(length--) {
        printf("%02x ", *(packet++));
        if((++chcnt % 16) == 0)
            printf("\n       ");
    }
    printf("   ");
    */
}

void packetfilter_callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int count = 1;
    struct libnet_ethernet_hdr *eth_header;     // struct ether_header 도 가능
    struct libnet_ipv4_hdr *ip_header;          // struct ip 도 가능
    struct libnet_tcp_hdr *tcp_header;          // struct tcphdr 도 가능

    unsigned short etherh_protocoltype;
    u_int8_t iph_protocol;
    int length = pkthdr->len;

    // get ethernet header
    eth_header = (struct libnet_ethernet_hdr *)packet;
    // get get ethernet header -> protocol type
    etherh_protocoltype = ntohs(eth_header->ether_type);

    printf("\n\n[Ethernet Packet info]\n");
    printf("   [*] Source MAC address : %s\n", ether_ntoa((const ether_addr *)eth_header->ether_shost));
    printf("   [*] Destination MAC address : %s\n", ether_ntoa((const ether_addr *)eth_header->ether_dhost));

    if(etherh_protocoltype == ETHERTYPE_IP) {
        // move to offset
        packet += sizeof(struct libnet_ethernet_hdr);
        // get ip header
        ip_header = (struct libnet_ipv4_hdr *)packet;
        iph_protocol = ip_header->ip_p;

        printf("[IP Packet info]\n");
        printf("   [*] IP packet header length : %d bytes (%d)\n", ip_header->ip_hl*4, ip_header->ip_hl);
        printf("   [*] Next Layer Protocol Type : %s(0x%x)\n", get_protocol_str(iph_protocol), iph_protocol);
        printf("   [*] Source IP : %s\n", inet_ntoa(ip_header->ip_src));
        printf("   [*] Destination IP : %s\n", inet_ntoa(ip_header->ip_dst));

        // move to next header offset
        packet += ip_header->ip_hl * 4;
        if(iph_protocol == IPPROTO_TCP) {
            // get tcp header
            tcp_header = (struct libnet_tcp_hdr *)packet;

            printf("[TCP Packet info]\n");
            printf("   [*] Control Flag : %s\b\b\b\n", get_tcp_flag_str(tcp_header->th_flags));
            printf("   [*] Source Port : %d\n", ntohs(tcp_header->th_sport));
            printf("   [*] Destination Port : %d\n", ntohs(tcp_header->th_dport));
            printf("   [*] Data(HEX, ASCII)\n");
            print_data(packet, length);

        }
        else {
            printf("[Unknown Packet]\n");
            printf("   [*] Not TCP Protocol ~~!\n");
            printf("   [*]    // TODO : other protocol handle");
        }
    }
    // IP 패킷이 아니라면
    else {
        printf("[Unknown Packet]\n");
        printf("   [*] Not IP Protocol ~~!\n");
        printf("   [*]    // TODO : other protocol handle");
    }
    printf("\n");
}

int main(int argc, char **argv) {
    char track[] = "취약점";
    char name[] = "이우진";
    char *dev;
    char *net_str;
    char *mask_str;
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;
    struct ether_header *eptr;
    const u_char *packet;

    struct bpf_program fp;

    pcap_t *pcd;    // packet capture descriptor

    printf("=====================================\n");
    printf("[bob5][%s]pcap_hw1[%s]\n\n", track, name);
    // get network dev name("ens33")
    dev = pcap_lookupdev(errbuf);       // dev = "ens33"으로 해도 무방
    if(dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEV: %s\n", dev);

    // get net, mask info
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if(ret == -1) {
        printf("%s\n", errbuf);
        exit(1);
    }

    // net, mask info to human_readable
    net_addr.s_addr = netp;
    net_str = inet_ntoa(net_addr);
    printf("NET : %s\n", net_str);

    mask_addr.s_addr = maskp;
    mask_str = inet_ntoa(mask_addr);
    printf("MASK : %s\n", mask_str);
    printf("=====================================\n");

    // dev 에 대한 packet capture descriptor를 pcd에 저장.
    // param1 : dev, param2 : snaplen(받아들일 수 있는 패킷의 최대 크기(byte),
    // param3 : promiscuous mode(1), non promisc(0), param4 : to_ms(time out)
    // param5 : error이면 NULL리턴 하고 ebuf에 에러 저장
    pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
    if(pcd == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }

    // filter option compile
    if(pcap_compile(pcd, &fp, "", 0, netp) == -1) {      //if(pcap_compile(pcd, &fp, "argv[2]", 0, netp) == -1) {
        printf("compile error\n");
        exit(1);
    }

    // filter option setting
    if(pcap_setfilter(pcd, &fp) == -1) {
        printf("setfilter error\n");
        exit(0);
    }

    // int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
    // param2(int cnt) : 패킷 캡쳐 몇번(0이면 infinite)
    // param3 : filtered packet이 들어오면 실행되는 handler callback func
    pcap_loop(pcd, 0, packetfilter_callback, NULL);     //pcap_loop(pcd, atoi(argv[1]), packetfilter_callback, NULL);

    return 0;
}
