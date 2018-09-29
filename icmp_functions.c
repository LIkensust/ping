#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#incldue <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>

#define K 1024
#define BUFFERSIZE 72

static unsigned short icmp_cksum(unsigned char *data,int len);//计算检验和
static void icmp_pack(struct icmp *icmph,int seq,struct timeval *tv,int length);//icmp报头填写
static int icmp_unpack(char *buf,int len);//icmp报头的剥离
static struct timeval icmp_tvsub(struct timeval end,struct timeval begin);//计算时间差
static void *icmp_send(void *argv)//发送报文
static void *icmp_recv(void *argv)//接受报文
static pingm_packet *icmp_findpacket(int seq);//在发送包状态数组中找一个位置
static void icmp_statistics(void);//打印最终的统计结果
static void icmp_sigint(int signo);//信号处理函数
static void icmp_usage();

typedef struct pingm_packet
{
	struct timeval tv_begin;
	struct timeval tv_end;
	short seq;
	int flag;
}pingm_packet;



static void icmp_sigint(int signo)
{
	alive = 0;
	gettimeofday(&tv_end,NULL);
	tv_internel = icmp_tvsub(tv_end,,tv_begin);
	return;
}

struct icmp
{
	u_int8_t icmp_type;		//消息类型
	u_int8_t icmp_code;		//消息代码
	u_int16_t icmp_cksum;	//16位检验和
	union					//
	{
		struct ih_idseq		//显示数据报
		{
			u_int16_t icd_id;	//数据报id
			u_int16_t icd_seq;	//数据报序号seq
		}ih_idseq;				//
	}icmp_hun;					//
#define icmp_id		icmp_hun._ih_idseq.ich_id
#define icmp_seq	icmp_hun._ih_idseq.ich_seq

	union
	{
		u_int8_t id_data[1];
	}icmp_dun;					//数据data
#define icmp_data	icmp_dun.id_data
};


static pingm_packet pingpacket[128];
static unsigned char send_buff[BUFFERSIZE];
static unsigned char recv_buff[2*K];
static struct sockaddr_in dest;
static int rawsock = 0;
static pid_t pid = 0;
static int alive = 0;
static short packet_send = 0;
static short packet_recv = 0;
static char dest_str[80];
static struct timeval tv_begin,tv_end,tv_internel;

int main(int argc,char *argv[])
{
	struct hostent * host =NULL;
	struct protected *protocol = NULL;
	char protoname[] = "icmp";
	unsigned long inaddr = 1;
	int size = 128*K;
	
	if(argc < 2)
	{
		icmp_usage();
		return -1;
	}
	
	protocol = getprotobyname(protoname);
	if(protocol == NULL)
	{
		perror("getprotobyname()");
		return -1;
	}
	
	memcpy(dest_str,argv[1],strlen(argv[1]+1));
	memset(pingpacket,0,sizeof(pingm_packet)*128);
	
	rawsock = socket(AF_INET,SOCK_RAM,protocol->p_proto);
	
	if(rawsock < 0)
	{
		perror("socker");
		return -1;
	}
	
	pid = getpid();
	
	setsockopt(rawsock,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size));//增大接受缓存区 防止接受的包被覆盖
	bzero(&dest,sizeof(dest));
	
	dest.sin_family = AF_INET;
	
	inaddr = inet_addr(argv[1]);
	if(inaddr == INADDR_NONE)//需要dns
	{
		host = gethostbyname(argv[1]);
		if(host == NULL)
		{
			perror("gethostbyname");
			return -1;
		}
		memcpy((char *)&dest.sin_addr,host->h_addr,host->h_length);
	}
	else
	{
		memcpy((char *)&dest.sin_addr,&inaddr,sizeof(inaddr));
	}
	
	inaddr = dest.sin_addr.s_addr;
	
	printf("PING %s (%d.%d.%d.%d) 56(84) bytes of data.\n",
			dest_str,
			(inaddr&0x000000FF)>>0,
			(inaddr&0x0000FF00)>>8,
			(inaddr&0x00FF0000)>>16,
			(inaddr&0xFF000000)>>24);
			
	signal(SIGINT,icmp_sigint);
	
	
	alive = 1;
	pthread_t send_id,recv_id;
	int err = 0;
	err = pthread_creade(&send_id,NULL,icmp_send,NULL);
	if(err < 0)
	{
		return -1;
	}
	err = pthread_create(&recv_id,NULL,icmp_recv,NULL);
	if(err < 0)
	{
		return -1;
	}
	
	pthread_join(send_id,NULL);
	pthread_join(recv_id,NULL);
	
	close(rawsock);
	icmp_statistics();
	return 0;
}






static void icmp_usage()
{
	fprintf(stderr,
			"中文输出的ping工具 1.0"
			"cping [ip]"
			"ctrl+c 退出");
	return;
}

static pingm_packet *icmp_findpacket(int seq)
{
	int i = 0;
	pingm_packet *found = NULL;
	//查找包的位置
	if(seq == -1)//-1表示查找的是空包的位置
	{
		for(i=0;i<128;i++)
		{
			if(pingpacket[i].flag == -1)
			{
				found = &pingpacket[i];
				break;
			}
		}
	}
	else if(seq >= 0) //查找对应的seq包
	{
		for(i=0;i<128;i++)
		{
			if(pingpacket[i].flag == seq)
			{
				found = &pingpacket[i];
				break;
			}
		}
	}
	return found;
}

static void icmp_statistics(void)
{
	long time = (tv_internel.tv_sec * 1000)+(tv_internel.tv_usec/1000);
	printf("--- %s ping statistics ---\n",dest_str);
	printf("%d packets transmitted, %d received, %d%c packet loss,time %d ms\n",
			packet_send,
			packet_recv,
			(packet_send-packet_recv)*100/packet_send,
			'%',
			time);
}

static unsigned short icmp_cksum(unsigned char *data,int len)
{
	int sum = 0;
	int odd = len & 0x01;//检查是否为奇数
	
	while(len & 0xfffe) //1111 1111 1111 1110  while(len > 1)
	{
		sum += *(unsigned short*)data;
		data += 2;
		len -=2;
	}
	
	if(odd)
	{
		unsigned short tmp = ((*data)<< 8)&0xff00); //补零 xxxxxxxx 00000000
		sum += tmp;
	}
	
	sum = (sum >> 16) + (sum & 0xffff); //高地位相加
	sum += (sum >> 16); //溢出位相加
	
	return ~sum;//结果取反
}

static void icmp_pack(struct icmp *icmph,int seq,struct timeval *tv,int length)//icmp报头填写  tv似乎没有被使用
{
	unsigned char i = 0;
	//设置报头
	icmph->icmp_type = ICMP_ECHO;
	icmph->icmp_code = 0;
	icmph->icmp_cksum = 0;
	icmph->icmp_seq = seq;
	icmph->icmp_id = pid & 0xffff;
	for( i = 0;i< length ; i++)
	{
		icmph->icmph_data[i] = i;
	}
	//set cksum
	icmpg->icmp_cksum = icmp_cksum((unsigned char*)icmph,length);
}

static int icmp_unpack(char *buf,int len)//icmp报头的剥离
{
	int i,iphdrlen;
	struct ip *ip = NULL;
	struct icmp *icmp = NULL;
	int rtt;
	
	ip = (struct ip*)buf;//ip首部
	iphdrlen = ip->ip_hl*4;//ip首部长度  因为是4字节为单位的 所以要乘4
	icmp = (struct icmp*)(buf + iphdrlen);//获得icmp报文的起始地址
	len -= iphdrlen;
	
	if(len<8)
	{
		printf("ICMP packets\'s length is less than 8\n'");
		return -1;
	}
	
	if((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid))//是一个echo回复报文 并且使本检查的ping的回复 不是其他进程的ping的回复
	{
		struct timeval tv_internel,tv_rece,tv_send;
		//在表格中查找已经发送的包  按照seq
		pingm_packet* packet = icmp_findpacket(icmp->icmp_seq);
		if(packet == NULL)
			return -1;
		
		packet->flag = 0;//取消标志
		tv_send = packet->tv_begin;//获取本包的发送时间
		gettimeofday(&tv_recv,NULL);//读取此刻时间 计算时间差		//这样是不是有问题？应当放在查找之前获取时间
		tv_internel = icmp_tvsub(tv_recv,tv_send);
		rtt = tv_internel.tv_sec*1000+tv_internel.tv_usec/1000;
		/*
			打印结果：
			icmp段长度
			源ip地址
			包的序列号
			TTL
			时间差
		*/
		printf("%d byte 来自 %s: icmp序号:%u 生存时间ttl:%d 回复时间rtt = %d ms\n",
				len,
				inet_ntoa(ip->ip_src),
				icmp->icmp_seq,
				ip->ip_ttl,
				rtt);
		
		packet_recv++;//接受包数据量加1
	}
	else
	{
		return -1;
	}
}

static struct timeval icmp_tvsub(struct timeval end,struct timeval begin)
{
	struct timeval tv;
	//计算时间差
	tv.tv_sec = end.tv_sec - begin.tv_sec;
	tv.tv_usec = end.tv_usec - begin.tv_usec;
	//如果接收时间的usec值小于发送时间的usec值 从sec域借位
	if(tv.tv_usec < 0)
	{
		tv.tv_sec --;
		tv.tv_usec += 1000000;
	}
	return tv;
}


static void *icmp_send(void *argv)//发送报文
{
	//保存程序开始发送数据
	gettimeofday(&tv_begin, NULL);
	while(alive)
	{
		int size = 0;
		struct timeval tv;
		gettimeofday(&tv, NULL);//获取程序的开始时间
		//在发送包状态数组中找一个空闲位置
		pingm_packet *packet = icmp_findpacket(-1);
		if(packet)
		{
			packet->seq = packet_send;//设置序号
			packet->flag = 1;
			gettimeofday( &packet->tv_begin,NULL);//设置发送时间
		}
		
		icmp_pack((struct icmp*)send_buff,packet_send,&tv,64);
		
		size = sendto(rawsock,send_buff,64,0,(struct sockaddr*)&dest,sizeof(struct sockaddr));
		
		if(size < 0)
		{
			perror("sendto error");
			continue;
		}
		
		packet_send++;
		//
		sleep(1);
	}
}


static void *icmp_recv(void *argv)
{
	//轮询等待时间
	struct timeval tv;
	tv.tv_sec = 200;
	tv.tv_usec = 0;
	fd_set readfd;
	while(alive)
	{
		int ret = 0;
		FD_ZERO(&readfd);
		FD_SET(rawsock,&readfd);
		ret = select(rawsock+1,&readfd,NULL,NULL,&tv);//IO复用
		switch(ret)
		{
			case -1:
				break;
			case 0:
				break;
			default:
			{
				//收到一个包
				int fromlen = 0;
				struct sockaddr from;
				//接受数据
				int size = recv(rawsock,recv_buff,sizeof(recv_buff),0);
				if(errno == EINTR)
				{
					perror("recvfrom error");
					continue;
				}
				//解包 并设置相关变量
				ret = icmp_unpack(recv_buff,size);
				if(ret == -1)
				{
					continue;
				}
			}
			break;
		}
	}
}




















