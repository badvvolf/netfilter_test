
#include <string>

#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <errno.h>
#include <netinet/ether.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <fstream>


#include <unordered_map>

using namespace std;


unordered_map <string, int> rule;
	

bool CheckHostHeader(uint8_t * data)
{
	char *savePtr;
	char * token;
	//차단할 대상인지 체크한다
	token = strtok_r((char *)data, "\n", &savePtr);
	
	while(token !=NULL && strncmp(token, "Host: ", 6))
	{
		token = strtok_r(NULL, "\n", &savePtr);
	}

	if(token == NULL)
		return false;

 
	token = strtok_r((char *)token, " ", &savePtr);

	if( rule[string(savePtr)] ==1 )
	{
		cout << "filtered : " << string(savePtr)<< endl;
		return true;
	}

	return false;

}



static bool Filtering(struct nfq_data *tb)
{

	struct nfqnl_msg_packet_hdr *ph;
	int ret;
	uint8_t *data;

	//다음 프로토콜이 TCP일 때만 처리
	ph = nfq_get_msg_packet_hdr(tb);
	if (ph)
	{
		if(ntohs(ph->hw_protocol) != ETHERTYPE_IP)
			return false;
	}
	
	//패킷 내용 받기
	ret = nfq_get_payload(tb, &data);

	if(ret>=0)
	{
		iphdr * ip = (iphdr * )data;
		u_int32_t iplen = (u_int32_t)(ip->ihl) * 4;
		
		tcphdr * tcp = (tcphdr *)((uint8_t *)data + iplen);

		//포트 80일 때만 잡음
		if(ntohs(tcp->dest) != 80)
			return false;

		//flag 체크 - 데이터 전송시에만 잡음
		if(!(tcp->ack && tcp->psh))
			return false;


		//http host header 체크
		uint8_t * http = (uint8_t *)((uint8_t *)tcp + (tcp->doff)*4);
		if(CheckHostHeader(http))
			return true;

	}

	return false;

}// static bool Filtering(struct nfq_data *tb)


static int Callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{

	uint32_t id;
	struct nfqnl_msg_packet_hdr *ph;

	uint32_t rule = NF_ACCEPT;


	ph = nfq_get_msg_packet_hdr(nfa);

	if (ph)
		id = ntohl(ph->packet_id);

	
	//필터링 대상일 시
	if(Filtering(nfa))
		rule = NF_DROP;
	
	//반응 설정
	return nfq_set_verdict(qh, id, rule, 0, NULL);


} //static int Callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));


	string filePath = "banList.csv";

	// read File
	ifstream banFile(filePath.data());
	if( banFile.is_open() ){
		string * line = new string();
		int i =0;
		while(getline(banFile, *line)){
    		rule[*line] = 1;
		}

		banFile.close();
	}
	else
	{
		printf("No banList.csv file\n");
		exit(1);
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h)
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &Callback, NULL);
	if (!qh)
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;)
	{
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
		{
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_put Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS)
		{
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	   it detaches other programs/sockets from AF_INET, too ! 
	*/
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);

}//int main(int argc, char **argv)