#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include <iostream>
#include <string>
#include <vector>

#include "mac.h"
#include "ip.h"
#include "iphdr.h"
#include "ethhdr.h"
#include "tcphdr.h"

using namespace std;

struct Packet{
    EthHdr eth_;
    IpHdr ip_;
    TcpHdr tcp_;
    char payload[60];
};

constexpr size_t MAX_PAYLOAD_SIZE=0x10;
const string tcp_data= "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
string pattern;

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}
void print_ether_mac(const struct libnet_ethernet_hdr* ethernet_header){
        printf("Ethernet - src mac: %s\n",ether_ntoa((ether_addr*)ethernet_header->ether_shost));
    printf("Ethernet - dst mac: %s\n",ether_ntoa((ether_addr*)ethernet_header->ether_dhost));
    return;
}
void print_ip(const struct libnet_ipv4_hdr* ipv4_header){
        struct in_addr src=ipv4_header->ip_src;
        struct in_addr dst=ipv4_header->ip_dst;
        printf("IP - src ip: %s\n", inet_ntoa(src));
        printf("IP - dst ip: %s\n", inet_ntoa(dst));
    return;
}
void print_port(const struct libnet_tcp_hdr* tcp_header){
        u_int16_t src=tcp_header->th_sport;
        u_int16_t dst=tcp_header->th_dport;
        printf("TCP - src port: %u\n",ntohs(src));
    printf("TCP - dst port: %u\n",ntohs(dst));
    return;
}
void print_payload(const u_char* payload,size_t payload_size){
        size_t print_size=payload_size<MAX_PAYLOAD_SIZE?payload_size:MAX_PAYLOAD_SIZE;
        printf("Payload (%zu byte(s)): ",payload_size);
        for(size_t i=0;i<print_size;i++){
            printf("%02x ",payload[i]);
        }
        if(payload_size>print_size)printf("...");
        printf("\n");
    return;
}

vector<int> getpi(string p){
    int siz=(int)p.size(),i,j=0;
    vector<int> pi(siz,0);
    for(i=1;i<siz;i++){
        while(j>0&&p[i]!=p[j]){
            j=pi[j-1];
        }
        if(p[i]==p[j]){
            pi[i]=j+1;
            j++;
        }
    }
    return pi;
}

bool kmp(string t,string p){
    vector<int> pi=getpi(p);
    int psiz=(int)p.size(),tsiz=(int)t.size(),i,j=0;
    for(i=0;i<tsiz;i++){
        while(j>0&&t[i]!=p[j]){
            j=pi[j-1];
        }
        if(t[i]==p[j]){
            if(j==psiz-1){
                return true;
                j=pi[j];
            }
            else j++;
        }
    }
    return false;
}

Mac get_mymac(const char* dev){
    struct ifreq ifr;
    u_char ret[32]={0,};

    int sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_IP);
    if(sock==-1){
        cerr << "mac socket open error\n";
        //fprintf(stderr,"mac socket open error\n");
        close(sock);
        exit(1);
    }

    strncpy(ifr.ifr_name,dev,IFNAMSIZ);
    if(ioctl(sock,SIOCGIFHWADDR,&ifr)!=0){
        cerr << "mac ioctl error\n";
        //fprintf(stderr,"mac ioctl error\n");
        close(sock);
        exit(1);
    }

    close(sock);
    memcpy(ret,ifr.ifr_hwaddr.sa_data,6);
    return Mac(ret);

}

size_t packet_data_len(Packet* packet){
    return (size_t)(ntohs(packet->ip_.ip_len)-(packet->ip_.ip_hl<<2)-(packet->tcp_.th_off<<2));
}

bool check_packet(Packet *packet){
    if(packet->eth_.type()!=EthHdr::Ip4)return false;
    if(packet->ip_.ip_p!=IPPROTO_TCP)return false;
    //if(!kmp(packet->payload,pattern))return false;
    //u_int32_t hlen=(u_int32_t)(ntohs(packet->ip_.ip_hl)*4+ntohs(packet->tcp_.th_off)*4);
    string payload=string((char*)&packet->ip_,ntohs(packet->ip_.ip_len));
    //cout<<"y\n";
    //cout<<payload.size()<<"size\n";
    if(!kmp(payload,pattern))return false;

    return true;
}



u_int16_t ip_checksum(IpHdr* header){
    //dump((u_char*)header,20);
    u_int32_t sum=0;
    u_int16_t imsi=header->ip_sum;
    u_short header_len=sizeof(IpHdr)>>1;
    header->ip_sum=0;
    u_int16_t* pseudo_header=(u_int16_t*)header;

    //cout<<header_len<<"whatthefuck\n";
    for(u_short i=0;i<header_len;i++){
        sum+=u_int32_t(ntohs(*pseudo_header++));
    }

    if(sum>0xffff)sum=(sum>>16)+(sum&0xffff);
    header->ip_sum=imsi;
    return ~(u_int16_t)sum;
}

u_int16_t tcp_checksum(IpHdr *ip, TcpHdr *tcp){
    /*cout<<"ip:\n";
    dump((u_char*)ip,20);
    cout<<"tcp:\n";
    dump((u_char*)tcp,100);*/
    u_int32_t sum=0;
    u_int16_t imsi=tcp->th_sum;
    tcp->th_sum=0;
    u_int32_t data_len=(u_int32_t)(ntohs(ip->ip_len))-sizeof(IpHdr);

    //src ip
    u_int32_t src=ip->ip_src();
    sum+=((src&0xffff0000)>>16)+(src&0x0000ffff);

    //dst ip
    u_int32_t dst=ip->ip_dst();
    sum+=((dst&0xffff0000)>>16)+(dst&0x0000ffff);

    //res

    //protocol
    sum+=(u_int32_t)ip->ip_p;

    //tcplen
    sum+=data_len;

    //tcp checksum
    data_len>>=1;
    //cout<<data_len<<"len\n";
    u_int16_t* pseudo_header=(u_int16_t*)tcp;
    for(u_int32_t i=0;i<data_len;i++){
        //cout<<hex<<u_int32_t(ntohs(*pseudo_header))<<" ";
        sum+=(u_int32_t)(ntohs((*pseudo_header++)));
    }
    if(data_len%2){
        sum+=(u_int32_t)(*(u_int8_t*)pseudo_header)<<8;
    }

    if(sum>0xffff)sum=(sum>>16)+(sum&0xffff);
    tcp->th_sum=imsi;

    return ~(u_int16_t)sum;
}

//rst
int send_packet_forward(pcap_t* pcap, Packet* captured_packet, Mac mymac){
    Packet* redirect_packet=new Packet;
    redirect_packet->eth_=captured_packet->eth_;
    redirect_packet->ip_=captured_packet->ip_;
    redirect_packet->tcp_=captured_packet->tcp_;
    //redirect_packet->payload.clear();

    //cout<<packet_data_len(captured_packet)<<"asdf\n";
    //eth
    redirect_packet->eth_.smac_=mymac;

    //ip
    redirect_packet->ip_.ip_len=htons(u_int16_t(sizeof(IpHdr)+sizeof(TcpHdr)));

    //tcp
    redirect_packet->tcp_.th_seq=htonl(ntohl(captured_packet->tcp_.th_seq)+packet_data_len(captured_packet));
    redirect_packet->tcp_.th_off=sizeof(TcpHdr)>>2;
    redirect_packet->tcp_.th_flags=TH_RST|TH_ACK;


    //dump((u_char*)redirect_packet,108);
    //checksum
    redirect_packet->ip_.ip_sum=htons(ip_checksum(&redirect_packet->ip_));

    redirect_packet->tcp_.th_sum=htons(tcp_checksum(&redirect_packet->ip_,&redirect_packet->tcp_));
    //cout<<hex<<redirect_packet->tcp_.th_sum<<"checksum\n";
    int res=pcap_sendpacket(pcap,(u_char*)redirect_packet,sizeof(EthHdr)+ntohs(redirect_packet->ip_.ip_len));
    if(res!=0){
        cerr << "pcap_sendpacket return " << res << " error=" << pcap_geterr(pcap) << "\n";
        delete redirect_packet;
        return 0;
    }

    delete redirect_packet;
    return 1;
}

//fin
int send_packet_backward(pcap_t* pcap, Packet* captured_packet, Mac mymac, string data){
    Packet* redirect_packet=new Packet();
    redirect_packet->eth_=captured_packet->eth_;
    redirect_packet->ip_=captured_packet->ip_;
    redirect_packet->tcp_=captured_packet->tcp_;
    //printf("packet-%p, ip-%p, tcp-%p, payload-%p ",redirect_packet,&redirect_packet->ip_,&redirect_packet->tcp_,&redirect_packet->payload);
    //redirect_packet->payload.clear();

    //eth
    redirect_packet->eth_.smac_=mymac;
    redirect_packet->eth_.dmac_=captured_packet->eth_.smac_;

    //ip
    swap(redirect_packet->ip_.ip_dst_,redirect_packet->ip_.ip_src_);
    redirect_packet->ip_.ip_len=htons(u_int16_t(sizeof(IpHdr)+sizeof(TcpHdr))+(u_int16_t)(data.size()));
    redirect_packet->ip_.ip_ttl=128;

    //tcp
    swap(redirect_packet->tcp_.th_dport,redirect_packet->tcp_.th_sport);
    swap(redirect_packet->tcp_.th_seq,redirect_packet->tcp_.th_ack);
    redirect_packet->tcp_.th_ack=htonl(ntohl(captured_packet->tcp_.th_seq)+packet_data_len(captured_packet));
    redirect_packet->tcp_.th_off=sizeof(TcpHdr)>>2;
    redirect_packet->tcp_.th_flags=TH_FIN|TH_ACK;

    //data
    for(int i=0;i<(int)data.size();i++)redirect_packet->payload[i]=data[i];
    redirect_packet->payload[data.size()]='\0';
    //memcpy((u_char*)(&redirect_packet->payload),data.c_str(),data.size());

    //dump((u_char*)(redirect_packet),150);
    //cout<<redirect_packet->payload<<"\nsize: "<<redirect_packet->payload.size()<<"\n";

    //checksum
    redirect_packet->ip_.ip_sum=htons(ip_checksum(&redirect_packet->ip_));
    redirect_packet->tcp_.th_sum=htons(tcp_checksum(&redirect_packet->ip_,&redirect_packet->tcp_));

    //cout<<hex<<redirect_packet->tcp_.th_sum<<"checksum\n";
    int res=pcap_sendpacket(pcap,(u_char*)redirect_packet,sizeof(EthHdr)+ntohs(redirect_packet->ip_.ip_len));
    if(res!=0){
        cerr << "pcap_sendpacket return " << res << " error=" << pcap_geterr(pcap) << "\n";
        delete redirect_packet;
        return 0;
    }

    delete redirect_packet;
    return 1;
}

void usage(){
    cout<<"syntax : tcp-block <interface> <pattern>\n";
    cout<<"sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n";
    return;
}

int main(int argc, char* argv[]) {

    if(argc!=3){
        usage();
        exit(1);
    }

    char* dev=argv[1];
    pattern=string(argv[2]);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    Mac mac=get_mymac(dev);
    //cout<<string(mac)<<"\n";
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        //printf("%u bytes captured\n", header->caplen);

        Packet* captured_packet=(Packet*)packet;
        //cout<<"x\n";
        if(check_packet(captured_packet)){
            cout<<"pattern captured\n";
            send_packet_forward(pcap,captured_packet,mac);
            //cout<<"forward clear\n";
            send_packet_backward(pcap,captured_packet,mac,tcp_data);
        }
        //cout<<"after\n";
            /*struct libnet_ethernet_hdr* ethernet_header=(libnet_ethernet_hdr*)packet;
            if(ntohs(ethernet_header->ether_type)!=ETHERTYPE_IP){
                    //not an ip protocol
                    printf("Not an ip protocol!\n");
                    printf("---------------------------------\n\n");
                    continue;
            }

            struct libnet_ipv4_hdr* ipv4_header=(libnet_ipv4_hdr*)(ethernet_header+1);
            if(ipv4_header->ip_p!=IPPROTO_TCP){
                    //not a tcp protocol
                    printf("Not a tcp protocol!\n");
                    printf("---------------------------------\n\n");
                    continue;
            }

            struct libnet_tcp_hdr* tcp_header=(libnet_tcp_hdr*)(ipv4_header+1);

            const u_int8_t tcp_header_size=(tcp_header->th_off)*4;
            size_t header_size=sizeof(libnet_ethernet_hdr)+sizeof(libnet_ipv4_hdr)+(size_t)tcp_header_size;

            const u_char* payload=(u_char*)(tcp_header)+tcp_header_size;

            print_ether_mac(ethernet_header);
            print_ip(ipv4_header);
            print_port(tcp_header);
            print_payload(payload,(size_t)header->caplen-header_size);
            printf("---------------------------------\n\n");*/
    }

    pcap_close(pcap);
}
