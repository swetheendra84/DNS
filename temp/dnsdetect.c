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
        u_short id;
        char ip[20][32];
	int offset;
        struct info *next;
};



void detect(struct info *node,const struct pcap_pkthdr *header,const u_char *packet)
{

struct sniff_ethernet *ether;
struct iphdr *ip;
struct udphdr *udp;
struct query question;
struct dns_header *dnsh;
int k;
int i=1;
int j=0;
char request[150], *dn;
ether = (struct sniff_ethernet *)(packet);
ip = (struct iphdr*)(((char*) packet) + 14);
udp = (struct udphdr*)(((char*) ip) + ip->ihl * 4);
dnsh = (struct dns_header*)(((char*) udp) + sizeof(struct udphdr));
question.qname = ((char*) dnsh) + 12;
int len;
        dn = question.qname;
        len = dn[0];
        while (len > 0) {
                for (k = 0; k < len; k++) {
                        request[j++] = dn[i + k];
                }
                request[j++] = '.';
                i += len;
                len = dn[i++];
                  }
        request[--j] = '\0';

int flag=0;
char *answer=(char *)question.qname+j+6;

u_short key=*((u_short *)dnsh->id);
u_int index;
char ippkt[32];
char list[20][32];
int l=0;
static int size=0;
for(int i=0;i<htons(*(u_short *)dnsh->anscount);i++)
{
	if(((u_short *)answer+2)[0]==1)
	{

	index=((u_int *)(answer+12))[0];
	sprintf(ippkt,"%u.%u.%u.%u",((u_char *)(&index))[0],((u_char *)&index)[1],((u_char *)&index)[2],((u_char *)&index)[3]);

		for(int j=0;j<size;j++)
		{
			if(key==node[j].id)
			{
			flag=1;			
			}
		}
		strcpy(list[l++],ippkt);
		answer=answer+16;
		
		
	}
	else
	{
		answer=answer+12+htons(((u_short *)answer+10)[0]);
	}
	
}

if(flag==0)
{
	for(i=0;i<l;i++)
	{
		node[size].id=key;
		strcpy(node[size].ip[i],list[i]);
	}
	node[size].offset=k;
	size=size+1;

}
if(flag==1)
{
	printf("Spoofing attempted on Transaction ID %d",key);

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
	struct info *head[50];
        char *file;
        struct info *first, *last;
        char *line = NULL;
        size_t len = 0;
        ssize_t read;
        char *token;
        char sip[32];
	char delimeter[] = " \t\n";

        memset(buf, 0, 1024);
	while ((opt = getopt(argc, argv, "i:r:")) != -1) {
       switch(opt)
        {
	case 'i':
        flag=1;
        dev=optarg;
        break;
        case 'r':
	printf("file is %s",optarg);
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
	

		if (pcap_lookupnet(dev, &net, &mask, buf) == -1) {
                perror("Couldn't get netmask for device");
                net=0;
                mask=0;
          	}
		if(flag1!=1)
		{		
		handle=pcap_open_live(dev,1518,1,1000,buf);
		if(handle==NULL)
		{
			perror("could not open device");
		}
		}
		else
		{
		handle=pcap_open_offline(file,buf);
		if(handle==NULL)	
		{
			perror("cannot open file");	

		}
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

        pcap_loop(handle, -1,(pcap_handler)detect,(u_char *) head);
        pcap_freecode(&fp);
        pcap_close(handle);

}
































































