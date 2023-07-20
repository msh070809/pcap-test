#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#define ETHER_HDT_LEN 14

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
    u_int8_t ip_hl:4;         /* 헤더 길이 */
    u_int8_t ip_v:4;          /* 버전 */
    u_int8_t ip_tos;          /* 서비스 유형 */
    u_int16_t ip_len;         /* 총 길이 */
    u_int16_t ip_id;          /* 식별자 */
    u_int16_t ip_off;         /* 오프셋 */
    u_int8_t ip_ttl;          /* 생존 시간(Time to Live) */
    u_int8_t ip_p;            /* 프로토콜 */
    u_int16_t ip_sum;         /* 체크섬 */
    struct in_addr ip_src;    /* 출발지 IP 주소 */
    struct in_addr ip_dst;    /* 목적지 IP 주소 */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* 출발지 포트 */
    u_int16_t th_dport;       /* 목적지 포트 */
    u_int32_t th_seq;         /* 시퀀스 번호 */
    u_int32_t th_ack;         /* 확인 응답 번호 */
    u_int8_t th_x2:4;         /* 사용되지 않음 */
    u_int8_t th_off:4;        /* 데이터 오프셋 */
    u_int8_t  th_flags;       /* 제어 플래그 */
    u_int16_t th_win;         /* 윈도우 크기 */
    u_int16_t th_sum;         /* 체크섬 */
    u_int16_t th_urp;         /* 긴급 포인터 */
};


void usage() {
        printf("syntax: pcap-test <interface>\n");
        printf("sample: pcap-test wlan0\n");

}

typedef struct {
        char* dev_;
} Param;

Param param = {
        .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
        if (argc != 2) {
                usage();
                return false;
        }
        param->dev_ = argv[1];
        return true;
}

int main(int argc, char* argv[]) {
        int i=0;
        if (!parse(&param, argc, argv))
                return -1;

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

	if(pcap == NULL) {
                fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
                return -1;
        }

        while (true) {
                struct pcap_pkthdr* header;
                const u_char* packet;
                int res = pcap_next_ex(pcap, &header, &packet);
                if (res == 0) continue;
                if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                        break;
                }
		struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)(packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr));
                struct libnet_ethernet_hdr* ethernet = (struct libnet_ethernet_hdr*)packet;
                struct libnet_ipv4_hdr* ipv4 = (struct libnet_ipv4_hdr*)(packet+sizeof(struct libnet_ethernet_hdr));
		const u_char* payload = packet+(sizeof(struct libnet_ethernet_hdr)+(ipv4->ip_hl*4)+(tcp->th_off*4));
		u_int16_t payload_length = header->caplen-ETHER_HDT_LEN-(ipv4->ip_hl*4)-(tcp->th_off*4);

                if(ipv4->ip_p==0x06)
                {
                    printf("src mac:");
                    printf("%02x %02x %02x %02x %02x %02x",ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
                    printf("/");
                    printf("des mac:");
                    printf("%02x %02x %02x %02x %02x %02x",ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
                    printf("\n");
		    printf("src ip:%s / des ip:%s\n",inet_ntoa(ipv4->ip_src),inet_ntoa(ipv4->ip_dst));
		    printf("src port:%d / des port:%d\n",ntohs(tcp->th_sport),ntohs(tcp->th_dport));
		    if(payload_length<10)
		    {
			printf("payload data:");
		    	for(i=0;i<payload_length;i++)
			{
			    printf("%02x ",*(payload+i));
			}
			for(i=0;i<10-payload_length;i++)
			{
				printf("00 ");
			}
		    }
		    else
		    {
                        printf("payload data:");
                        for(i=0;i<10;i++)
                        {
                            printf("%02x ",*(payload+i));
                        }
		    }
		    printf("\n");
		    printf("-----------------------\n");
                }
               	else
		{
			continue;
		}
		
        }
        pcap_close(pcap);
}

