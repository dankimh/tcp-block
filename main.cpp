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
        close(sock);
        exit(1);
    }

    strncpy(ifr.ifr_name,dev,IFNAMSIZ);
    if(ioctl(sock,SIOCGIFHWADDR,&ifr)!=0){
        cerr << "mac ioctl error\n";
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
    string payload=string((char*)&packet->ip_,ntohs(packet->ip_.ip_len));
    if(!kmp(payload,pattern))return false;
    return true;
}



u_int16_t ip_checksum(IpHdr* header){
    u_int32_t sum=0;
    u_int16_t imsi=header->ip_sum;
    u_short header_len=sizeof(IpHdr)>>1;
    header->ip_sum=0;
    u_int16_t* pseudo_header=(u_int16_t*)header;

    for(u_short i=0;i<header_len;i++){
        sum+=u_int32_t(ntohs(*pseudo_header++));
    }

    if(sum>0xffff)sum=(sum>>16)+(sum&0xffff);
    header->ip_sum=imsi;
    return ~(u_int16_t)sum;
}

u_int16_t tcp_checksum(IpHdr *ip, TcpHdr *tcp){
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
    u_int16_t* pseudo_header=(u_int16_t*)tcp;
    for(u_int32_t i=0;i<data_len;i++){
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

    //eth
    redirect_packet->eth_.smac_=mymac;

    //ip
    redirect_packet->ip_.ip_len=htons(u_int16_t(sizeof(IpHdr)+sizeof(TcpHdr)));

    //tcp
    redirect_packet->tcp_.th_seq=htonl(ntohl(captured_packet->tcp_.th_seq)+packet_data_len(captured_packet));
    redirect_packet->tcp_.th_off=sizeof(TcpHdr)>>2;
    redirect_packet->tcp_.th_flags=TH_RST|TH_ACK;

    //checksum
    redirect_packet->ip_.ip_sum=htons(ip_checksum(&redirect_packet->ip_));

    redirect_packet->tcp_.th_sum=htons(tcp_checksum(&redirect_packet->ip_,&redirect_packet->tcp_));
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

    //checksum
    redirect_packet->ip_.ip_sum=htons(ip_checksum(&redirect_packet->ip_));
    redirect_packet->tcp_.th_sum=htons(tcp_checksum(&redirect_packet->ip_,&redirect_packet->tcp_));

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
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        Packet* captured_packet=(Packet*)packet;
        if(check_packet(captured_packet)){
            cout<<"pattern captured\n";
            send_packet_forward(pcap,captured_packet,mac);
            send_packet_backward(pcap,captured_packet,mac,tcp_data);
        }
    }
    pcap_close(pcap);
}
