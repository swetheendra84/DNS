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

static int array_size=0;

void detect(struct info *database,const struct pcap_pkthdr *header,const u_char *packet)
{

 struct ethernet_header *ether;
        struct iphdr *ip;
        struct udphdr *udp;
        struct query question;
        struct dns_header *dns_hdr;
        u_int ip_header_size;
        char request[150], *domain_name;
        int size, i = 1, j = 0, k;
        int possible_attack;
        char new_ip_list[20][32];
        char ip_from_pkt[32];
        int id_found;
        char *hex_id;
        int index_in_db;
        u_short id;
        char *answer_start;
        u_int ip_index;
        u_short type, class, resp_size;
        int epoch_time;         /* for calculating time for packet */
        time_t epoch_time_as_time_t;
        struct tm * timeinfo;

        /* define ethernet header */
        ether = (struct ethernet_header*)(packet);
        ip = (struct iphdr*)(((char*)packet) + 14);
	ip_header_size = ip->ihl * 4;
        udp = (struct udphdr*)(((char*) ip) + ip_header_size);

        /* dns header */
        dns_hdr = (struct dns_header*)(((char*) udp) + sizeof(struct udphdr));

        /* start of question */
        question.qname = ((char *)dns_hdr + 12);

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
answer_start = (char *)question.qname + j + 6;

        /* Saving current ID of DNS */
        id = *((u_short *)dns_hdr->id);
        hex_id = dns_hdr->id;

        possible_attack = 0;
        k = 0;  // This value of k is used as a reference in other places. Shouldn't be touched.
        for (i = 0; i < htons(*((u_short *)(dns_hdr->anscount))); i++) {
                type = ((u_short *)(answer_start + 2))[0];
                class = ((u_short *)(answer_start + 4))[0];
                resp_size = ((u_short *)(answer_start + 10))[0];

                id_found = 0;
                if (htons(type) == 1) { // Evaluate only if Type A
                        ip_index = ((u_int *)(answer_start + 12))[0]; // get index of IP in packet
                        sprintf(ip_from_pkt, "%u.%u.%u.%u", ((u_char *)(&ip_index))[0],
                                ((u_char *)(&ip_index))[1],
                                ((u_char *)(&ip_index))[2],
                                ((u_char *)(&ip_index))[3]);

                        /* check if ID already present in database, and hence an attack */
                        for (j = 0; j < array_size; j++) {
  if (id == database[j].id) {
                                        index_in_db = j;
                                        possible_attack = 1;
                                        id_found = 1;
                                }
                        }

                        /* creat a list of all the IPs in this answer */
                        strcpy(new_ip_list[k++], ip_from_pkt);

                        /* new answer starts at previous answer position + 16 (size of type A) */
                        answer_start = answer_start + 16;
                } else {        // skip evaluating other types (like type CNAME for instance)
                        /* new answer starts at previous answer position
                         * + 12 (all fields excpt response size)
                         * + response size
                         */
                        answer_start = answer_start + 12 + htons(resp_size);
                }


        }
if (id_found == 0) {
                for (i = 0; i < k; i++) {
                        database[array_size].id = id;
                        strcpy(database[array_size].ip[i], new_ip_list[i]);
                }
                database[array_size].offset = k;
                array_size += 1;
        }

        /* warn user if possible attack */
        if (possible_attack == 1) {
                /* get time from packet header */
                epoch_time = header->ts.tv_sec;
                epoch_time_as_time_t = epoch_time;
                timeinfo = localtime(&epoch_time_as_time_t);

                printf("\nDNS poisoning attempt detected!!!\n");
                printf("Timestamp: %s", asctime(timeinfo));
                printf("TXID: 0x");
                printf("%x", (int)(*(u_char *)(hex_id)));
                printf("%x\t", (int)(*(u_char *)(hex_id + 1)));
                printf("Request: %s\n", request);
		           for (i = 0; i < database[index_in_db].offset; i++) {
                        if (i + 1 == database[index_in_db].offset) {
                                printf("%s", database[index_in_db].ip[i]);
                        } else {
                                printf("%s, ", database[index_in_db].ip[i]);
                        }
                }
                printf("]\n");
                printf("Answer2 [");
                for (i = 0; i < k; i++) {
                        if (i + 1 == k) {
                                printf("%s", new_ip_list[i]);
                        } else {
                                printf("%s, ", new_ip_list[i]);
                        }
                }
                printf("]\n");
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
































































