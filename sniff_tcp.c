#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h" // 기존 헤더 파일 그대로 활용

// 패킷 캡처 시마다 호출되는 콜백 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // IP 패킷인지 확인
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        // TCP 패킷인지 확인
        if (ip->iph_protocol == IPPROTO_TCP) {
            int ip_header_len = ip->iph_ihl * 4;
            struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
            int tcp_header_len = TH_OFF(tcp) * 4;

            // Ethernet 헤더 출력
            printf("Ethernet Header\n");
            printf("   Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("   Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            // IP 헤더 출력
            printf("IP Header\n");
            printf("   Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
            printf("   Dst IP  : %s\n", inet_ntoa(ip->iph_destip));

            // TCP 헤더 출력
            printf("TCP Header\n");
            printf("   Src Port: %u\n", ntohs(tcp->tcp_sport));
            printf("   Dst Port: %u\n", ntohs(tcp->tcp_dport));

            // 메시지 시작 위치 및 길이 계산
            const u_char *message = (u_char *)tcp + tcp_header_len;
            int message_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

            // 캡처 범위 제한
            if (message_len > header->caplen) message_len = header->caplen;
            if (message_len > 256) message_len = 256;

            if (message_len > 0) {
                printf("Message\n   ");
                for (int i = 0; i < message_len; i++) {
                    printf("%c", message[i]);
                }
                if (message_len == 256) printf("..."); // 메시지지 길이 제한 ... 으로 마무리
            }

            printf("\n---------------------------------------------\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // eth0 인터페이스에서 패킷 캡처
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    // TCP 패킷 필터 적용
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // 캡처 루프
    pcap_loop(handle, -1, got_packet, NULL);

    // 핸들 해제
    pcap_close(handle);
    return 0;
}
