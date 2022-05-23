#include "vpnBase.h"
#include "threadpool.h"
#include "epoller.h"
#include "ipGenerator.h"
#include <unordered_map>
#include <vector>

using std::string;
using std::thread;
using std::unordered_map;

const int BUFF_SIZE = 2000;
const int PORT_NUMBER = 4433;

const uint32_t LISTEN  = (EPOLLIN | EPOLLRDHUP);
const uint32_t SOCKIN  = (EPOLLRDHUP | EPOLLIN  | EPOLLERR | EPOLLHUP | EPOLLONESHOT);
const uint32_t SOCKOUT = (EPOLLRDHUP | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLONESHOT);

// default 192.168.60.0/24
const char* intranetip = "192.168.60.0";

class vpnserver : protected vpnBase
{
public:
	vpnserver();
	void start();

private:
	using realSockHitType = void(vpnserver::*)(int);
	SSL* generateSSL(const char* hostip = nullptr) override final;
	virtual void tunHit() override;
	virtual void socketHit() override final { assert(0); };
	void   socketHit(int cfd);
	void   initTCPServer();
	void   setupConnection();
	void   closeConnection(int cfd);
	// void   distributeTunnelIP(SSL*);
	inline uint32_t getIPfromData(const char* buf, const int len) const;
	inline int  getlow16bit(uint32_t) const;
	inline int gethigh16bit(uint32_t) const;
	inline void transform_ntoa(string& ret, const uint32_t baseip) const;

private:
	// uint32_t baseip;
	int    	listenfd;
	string 	hostip;
	std::vector<uint32_t>  fdipTable;
	// std::unordered_map<int, SSL*> fdToSSL;
	std::unordered_map<uint32_t, SSL*> ipToSSL;
	std::unique_ptr<epoller> eper;
	std::unique_ptr<threadpool> pool;
	std::unique_ptr<TunnelIPGenerator> ipGenerator;
};

// baseip(0xc0a83501),

vpnserver::vpnserver() : fdipTable(10004, 0), eper(new epoller), pool(new threadpool(8)), ipGenerator(new TunnelIPGenerator)
{
	initializeSSL(SERVERCERT, SERVERKEY, true);
	// ssl = generateSSL();
	// assert(ssl != nullptr);
	createTUNDevice();
	string baseAddr;
	transform_ntoa(baseAddr, ipGenerator->getIPfromPool());
	setupTUNIPaddr(baseAddr.c_str());
	// baseip++;
	initTCPServer();
}

SSL* vpnserver::generateSSL(const char* ) {
	return SSL_new(ctx);
}

void vpnserver::tunHit()
{
	int len;
	char buff[BUFF_SIZE];
	fd_set tunFDSet;
	uint32_t  dstip;
	unordered_map<uint32_t, SSL*>::iterator iter;

	do {

		FD_ZERO(&tunFDSet);
		FD_SET(tunfd, &tunFDSet);
		select(FD_SETSIZE, &tunFDSet, NULL, NULL, NULL);

		if (FD_ISSET(tunfd, &tunFDSet)) {

			bzero(buff, BUFF_SIZE);
			len = read(tunfd, buff, BUFF_SIZE);
			printf("Got a packet from TUN\n");

			uint8_t version = buff[0];
			version >>= 4;
			if (version == 6)
				break;

			parseDstaddr(buff, len);
			dstip = getIPfromData(buff, len);
			printf("dstip : %u\n", dstip);
			iter = ipToSSL.find(dstip);
			if (iter == ipToSSL.end()) {
				printf("Can't find it, maybe ip tun0 changed by client manually\n");
				break;
			}
			// write(fd, buff, len);
			SSL_write(iter->second, buff, len);
			printf("SENT TO ...\n");
		}

	} while (0);
	eper->modfd(tunfd, SOCKIN);
}

void vpnserver::socketHit(int cfd)
{
	int len;
	char buff [BUFF_SIZE];
	unordered_map<uint32_t, SSL*>::iterator iter;

	printf("Got a packet from the tunnel\n");
	iter = ipToSSL.find(fdipTable[cfd]);
	if (iter == ipToSSL.end())
		return;
	bzero(buff, BUFF_SIZE);
	len = SSL_read(iter->second, buff, BUFF_SIZE);
	printf("tunfd : %d, ssl : %p, buff : %p, len : %d\n", tunfd, iter->second, buff, len);
	if (len < 0 && errno == EAGAIN) {
		return;
	} else if (len <= 0) {
		printf("close cfd %d\n", cfd);
		closeConnection(cfd);
		// exit(0);
	} else {
		write(tunfd, buff, len);
		eper->modfd(cfd, SOCKIN);
	}
}

inline uint32_t vpnserver::getIPfromData(const char* buf, const int len) const {
	assert(len >= 20);
	uint32_t ret = ((uint8_t)buf[16] << 24);
	ret |= ((uint8_t)buf[17] << 16);
	ret |= ((uint8_t)buf[18] << 8);
	ret |= ((uint8_t)buf[19]);
	return ret;
}

inline int vpnserver::getlow16bit(uint32_t baseip) const {
	return (0x0000ffff & baseip);
}

inline int vpnserver::gethigh16bit(uint32_t baseip) const {
	return (baseip >> 16);
}

inline void vpnserver::transform_ntoa(string& ret, const uint32_t baseip) const {
	ret = std::to_string(baseip >> 24) + "."
	      + std::to_string((baseip >> 16) & 0xff) + "."
	      + std::to_string((baseip >> 8) & 0xff) + "."
	      + std::to_string(baseip & 0xff);
}

void vpnserver::initTCPServer()
{

	sockaddr_in server;

	memset(&server, 0, sizeof(server));

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(PORT_NUMBER);

	listenfd = socket(PF_INET, SOCK_STREAM, 0);
	CHK_ERR(listenfd, "Create socket");

	int optval = 1;
	int ret = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&optval, sizeof(int));
	CHK_ERR(ret, "REUSERADDR");

	ret = bind(listenfd, (struct sockaddr *) &server, sizeof(server));
	CHK_ERR(ret, "bind");

	ret = listen(listenfd, 5);
	CHK_ERR(ret, "listen");
	printf("listening...\n");

	eper->addfd(listenfd, LISTEN);

}

void vpnserver::setupConnection()
{
	uint32_t ipaddr;
	string distributeIP;
	string intranet = intranetip;
	sockaddr_in peerAddr;
	socklen_t peerAddrLen = sizeof(peerAddr);

	int cfd = accept(listenfd, (sockaddr*)&peerAddr, &peerAddrLen);
	CHK_ERR(cfd, "accept");

	printf("Accept connect from client %s.\n", inet_ntoa(peerAddr.sin_addr));
	SSL* ssl = generateSSL();
	assert(ssl != nullptr);
	int x = SSL_set_fd(ssl, cfd);
	assert(x > 0);

	x = SSL_accept(ssl);
	// assert(x > 0);
	// CHK_SSL(x);
	if (x < 0) {
		printf("\033[1;31mACCEPT ERROR : maybe verification failed\n");
		ERR_print_errors_fp(stderr);
		puts("\033[0mclose cfd");
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(cfd);
		return;
	}

	ipaddr = ipGenerator->getIPfromPool();

	if (ipaddr == 0) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(cfd);
		printf("\033[31mipaddrs are all distributed\n");
		return;
	}

	// fdToSSL.emplace(cfd, ssl);
	// ipToSSL.emplace(baseip, ssl);
	ipToSSL.emplace(ipaddr, ssl);
	assert(fdipTable[cfd] == 0);
	// fdipTable[cfd] = baseip;
	fdipTable[cfd] = ipaddr;
	// distributeTunnelIP(ssl);
	printf("distribute : %x\n", ipaddr);
	transform_ntoa(distributeIP, ipaddr);
	SSL_write(ssl, distributeIP.c_str(), distributeIP.size());
	SSL_write(ssl, intranet.c_str(), intranet.size());
	printf("send\n");

	eper->addfd(cfd, SOCKIN);

}


void vpnserver::closeConnection(int cfd)
{
	eper->delfd(cfd);
	// fdToSSL.erase(cfd);
	uint32_t &ref = fdipTable[cfd];
	assert(ref != 0);
	SSL* ssl = ipToSSL[ref];
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(cfd);
	ipToSSL.erase(ref);
	ipGenerator->releaseIP(ref);
	ref = 0;
}

void tunSelected(SSL* ssl, int tunfd)
{
	int len;
	char buff[BUFF_SIZE];


	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE);
	printf("Got a packet from TUN\n");
	uint8_t version = buff[0];
	version >>= 4;
	if (version == 6)	return;
	parseDstaddr(buff, len);
	// write(fd, buff, len);
	SSL_write(ssl, buff, len);
}

void vpnserver::start()
{

	setupConnection();

	eper->addfd(tunfd, SOCKIN);

	while (1) {
		int n = eper->wait();
		assert(n != -1);
		epoll_event* events = eper->getEvents();
		for (int i = 0; i < n; i++) {
			int fd = events[i].data.fd;
			uint32_t event = events[i].events;
			if (fd == tunfd) {
				pool->addTask(std::bind(&vpnserver::tunHit, this));
			} else if (fd == listenfd) {
				setupConnection();
			} else {
				if (event & EPOLLIN) {
					pool->addTask(std::bind((realSockHitType)&vpnserver::socketHit, this, fd));
				} else if (event & (EPOLLRDHUP | EPOLLHUP | EPOLLERR) ) {
					printf("close cfd %d\n", fd);
					closeConnection(fd);
				} else if (event & EPOLLOUT) {
					;
				} else {
					printf("Undefined Behavior\n");
				}
			}

		}
	}
}