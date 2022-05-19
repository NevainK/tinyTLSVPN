#ifndef VPNCLIENT_H
#define VPNCLIENT_H

#include <string>
#include "vpnBase.h"

using std::string;

const int BUFF_SIZE = 2000;
const int PORT_NUMBER = 4433;

const char* intranetMask = "255.255.255.0";

class vpnclient : protected vpnBase
{
public:
	vpnclient() = delete;
	~vpnclient();
	explicit vpnclient(const char* hostip);
	void start();

private:
	SSL* generateSSL(const char* hostip) override final;
	virtual void tunHit() override;
	virtual void socketHit() override;
	void connectToServer(const char *svrip);
	void addRouteintranet(const char *dstnet, char* dev, const char* netmask = intranetMask, const char* gateway = nullptr);

private:

	int sockfd;
	SSL*   ssl;
	string hostip;
};

vpnclient::vpnclient(const char* hostipstr) : sockfd(0), ssl(nullptr), hostip(hostipstr)  {

	// is IPV4 ? ?
	int p1 = hostip.find_first_of('.') + 1;
	int p2 = hostip.find_first_of('.', p1) + 1;
	int p3 = hostip.find_first_of('.', p2) + 1;
	assert( p1 && p2 && p3 );
	int val1 = stoi(hostip);
	int val2 = stoi(hostip.substr(p1, 3));
	int val3 = stoi(hostip.substr(p2, 3));
	int val4 = stoi(hostip.substr(p3, 3));
	assert((val1 < 255 && val1 > 0) && (val2 <= 255 && val2 >= 0)
	       && (val3 <= 255 && val3 >= 0) && (val4 <= 255 && val4 > 0));

	initalizeSSL(CLIENTCERT, CLIENTKEY, false);
	ssl = generateSSL(hostip.c_str());
	assert(ssl != nullptr);
	createTUNDevice();
}

vpnclient::~vpnclient()
{
	printf("client close\n");
	SSL_CTX_free(ctx);
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
		ssl = nullptr;
	}
	close(sockfd);
}

SSL* vpnclient::generateSSL(const char *hostip)
{
	SSL* ssl;
	ssl = SSL_new(ctx);

	X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);

	X509_VERIFY_PARAM_set1_host(vpm, hostip, 0);

	return ssl;
}

void vpnclient::connectToServer(const char* svrip)
{
	sockaddr_in peerAddr;

	memset(&peerAddr, 0, sizeof(peerAddr));
	peerAddr.sin_family = AF_INET;
	peerAddr.sin_port = htons(PORT_NUMBER);
	peerAddr.sin_addr.s_addr = inet_addr(svrip);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(sockfd, "Create TCP client");

	int ret = connect(sockfd, (sockaddr*)&peerAddr, sizeof(peerAddr));
	CHK_ERR(ret, "connect");

	printf("Connect to server %s\n", inet_ntoa(peerAddr.sin_addr));

	int x = SSL_set_fd(ssl, sockfd);
	printf("sockfd : %d, x = %d\n", sockfd, x);
	assert(x > 0);
	int err = SSL_connect(ssl);
	assert(err > 0);
	printf("SSL connect succeccfully!\n");

	char buf[30] = {0};
	// write(sockfd, buf, 8); // read(sockfd, buf + 7, 90);
	// SSL_write(ssl, buf, 8);
	SSL_read(ssl, buf, 29);
	printf("recv: %s\n", buf);
	setupTUNIPaddr(buf);

	memset(buf, 0, sizeof(buf));
	SSL_read(ssl, buf, 29);
	printf("recv : %s\n", buf);
	char dev[6] = "tun0";
	addRouteintranet(buf, dev);
}

void vpnclient::socketHit()
{
	assert(SSL_get_fd(ssl) != -1);

	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from the tunnel\n");

	bzero(buff, BUFF_SIZE);
	len = SSL_read(ssl, buff, BUFF_SIZE);
	if (len < 0 && errno == EAGAIN) {
		return;
	} else if (len <= 0) {
		printf("server close or error\n");
		exit(0);
	} else {
		write(tunfd, buff, len);
	}
}

void vpnclient::tunHit()
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from TUN\n");

	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE);
	parseDstaddr(buff, len);
	printf("from TUN len : %d\n", len);
	SSL_write(ssl, buff, len);
}

void vpnclient::addRouteintranet(const char* dstnet, char* dev, const char* netmask, const char* gateway)
{
	int fd;
	int rc = 0;
	sockaddr_in sin;
	rtentry  rt;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(fd > 0);

	memset(&rt, 0, sizeof(rt));
	memset(&sin, 0, sizeof(sin));

	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	rt.rt_flags = RTF_UP;

	if (gateway) {
		assert(inet_aton(gateway, &sin.sin_addr)  == 1);
		memcpy ( &rt.rt_gateway, &sin, sizeof(sin));
		rt.rt_flags = RTF_GATEWAY;
	}

	assert(dstnet != nullptr);
	((struct sockaddr_in *)&rt.rt_dst)->sin_family = AF_INET;
	assert(inet_aton(dstnet, &((struct sockaddr_in *)&rt.rt_dst)->sin_addr) == 1);

	assert(netmask != nullptr);
	((struct sockaddr_in *)&rt.rt_genmask)->sin_family = AF_INET;
	assert(inet_aton(netmask, &((struct sockaddr_in *)&rt.rt_genmask)->sin_addr) == 1);

	assert(dev != nullptr);
	rt.rt_dev = dev;
	assert(ioctl(fd, SIOCADDRT, &rt) >= 0);
	close(fd);
}

void vpnclient::start()
{
	printf("tunfd : %d\n", tunfd);

	connectToServer(hostip.c_str());

	while (1) {
		fd_set readFDSet;

		FD_ZERO(&readFDSet);
		FD_SET(sockfd, &readFDSet);
		FD_SET(tunfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

		if (FD_ISSET(tunfd, &readFDSet)) {
			tunHit();
		}
		if (FD_ISSET(sockfd, &readFDSet)) {
			socketHit();
		}
	}
}

#endif