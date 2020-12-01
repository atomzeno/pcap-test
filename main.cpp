#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define ethsize 6
void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
    printf("sample: pcap-test ens33 at ubuntu\n");
}


void print_eth_host_dest(int type, u_int8_t ethhost[ethsize]){
    if(type==1){
        printf("Dst");
    }
    else{
        printf("Src");
    }
    printf(" mac address : [");
    int i;
    for(i=0;i<ethsize;i++){
        if(i!=0){
            printf(":");
        }
        printf("%02x",(u_int8_t)ethhost[i]);
    }
    printf("]\n");
}

void print_Ethernet_Header(struct libnet_ethernet_hdr* packet_eth){
    printf("--------------Ethernet Header--------------\n");
    print_eth_host_dest(0, packet_eth->ether_shost);
    print_eth_host_dest(1, packet_eth->ether_dhost);
    //16bit, network byte order --> host byte order chanded at main
    printf("Ethertype : %04x\n",packet_eth->ether_type);
}

int main(int argc, char* argv[]) {

    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
    int packet_number=0;
    while (true) {
        int i;
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        ++packet_number;
        //packet analyze
        struct libnet_ethernet_hdr* packet_eth=(struct libnet_ethernet_hdr *)(packet);
        packet_eth->ether_type=ntohs(packet_eth->ether_type);

        if(packet_eth->ether_type != ETHERTYPE_IP){//ipv4 use X
            printf("This packet don't use ipv4!");
            continue;
        }
        int eth_header_size=(int)sizeof(struct libnet_ethernet_hdr);
        struct libnet_ipv4_hdr *packet_ip=(struct libnet_ipv4_hdr *)(packet + eth_header_size);
        if(packet_ip->ip_p!=IPPROTO_TCP){//protocol isn't tcp
            continue;
        }
        printf("--------------Packet analyze--------------\n");
        printf("size of eth header : %d\n",eth_header_size);
        printf("This packet is %dth\n", packet_number);
        printf("%u bytes captured\n", header->caplen);
        print_Ethernet_Header(packet_eth);
        //ethernet part ended
        printf("--------------IP Header--------------\n");
        printf("IP version : %#02x\n", packet_ip->ip_v);
        printf("IP protocol : %#02x\n", packet_ip->ip_p);
        printf("IP header length : %#02x\n", packet_ip->ip_hl << 2);
        int total_packet_length=(int)ntohs(packet_ip->ip_len);
        printf("IP header, total packet length : %d\n", total_packet_length);

        printf("Src ip : %s \n",inet_ntoa(packet_ip->ip_src));
        printf("Dst ip : %s \n",inet_ntoa(packet_ip->ip_dst));

        //printf("ip_hl : %#02x\n",packet_ip->ip_hl);
        //ip part ended
        int ip_header_length = ((int)packet_ip->ip_hl)*4;
        int tcp_header_offset = ip_header_length + eth_header_size;//word --> byte, * 4
        //ip_hl : ip's header length
        //printf("tcp_header_offset : %d\n",tcp_header_offset);

        struct libnet_tcp_hdr *packet_tcp=(struct libnet_tcp_hdr *)(packet + tcp_header_offset);
        printf("--------------TCP Header--------------\n");
        printf("Src port : %d\n", (int)ntohs(packet_tcp->th_sport));
        printf("Dst port : %d\n", (int)ntohs(packet_tcp->th_dport));

        //u_int16_t th_sport;       /* source port */
        //u_int16_t th_dport;       /* destination port */
        int tcp_header_length = ((int)packet_tcp->th_off)*4;

        int packet_data_offset=tcp_header_offset+tcp_header_length;
        //word to byte, *4, data offset
        //printf("%#02x\n",packet_tcp->th_off);
        //printf("packet_data_offset : %d\n",packet_data_offset);
        u_int8_t * packet_output=(u_int8_t *)(packet + packet_data_offset);
        printf("--------------Payload--------------\n");
        //printf("packet's payload is %d bytes\n", (header->caplen-packet_data_offset));
        int packet_length=total_packet_length-ip_header_length-tcp_header_length;
        printf("packet's payload is %d bytes\n", packet_length);
        packet_length=(packet_length < 16 ? packet_length : 16);
        if(packet_length!=0){
            printf("packet's %d byte data : ", packet_length);
            for(i=0;i<16 && i<(packet_length);i++){
                printf("%c",packet_output[i]);
            }
        }
        printf("\n\n");
    }

    pcap_close(handle);

}
