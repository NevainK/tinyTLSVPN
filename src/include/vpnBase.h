#ifndef VPNBASE_H
#define VPNBASE_H

#include <assert.h>
#include <fcntl.h>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <net/route.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

#define CHK_NULL(x)		do { if ((x)==NULL) exit (1); } while(0)
#define CHK_ERR(err,s)	do { if ((err)==-1) { perror(s);printf("errno : %d\n", errno); exit(1); } } while(0)
#define CHK_SSL(err)	do { if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); } } while(0)

#define HOME 		"./cert_server/"
#define SERVERCERT	HOME"server.crt"
#define SERVERKEY	HOME"server.key"
#define CLIENTCERT  HOME"client.crt"
#define CLIENTKEY   HOME"client.key"
#define CACERT		HOME"ca.crt"

const int defaultmask = 21;

int verify_callback(int preverify_ok, X509_STORE_CTX * x509_ctx)
{
	char buf[300];

	X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
	printf("subject= %s\n", buf);

	if (preverify_ok == 1) {
		printf("Verification passed.\n");
		return 1;
	} else {
		int err = X509_STORE_CTX_get_error(x509_ctx);
		printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
		switch (err)
		{
		case X509_V_ERR_CERT_HAS_EXPIRED :
			return 0;
		default:
			return 1;
		}
	}
}

class vpnBase {

public:

	// vpnBase() = delete;

	void initializeSSL(const char* certificatefile, const char* privatekeyfile, bool isServer);
	virtual SSL* generateSSL(const char* hostname) = 0;
	void createTUNDevice();
	void setupTUNIPaddr(const char* fixedip, const int maskbit = defaultmask);

	virtual void tunHit() = 0;
	virtual void socketHit() = 0;

protected:

	int tunfd;

	SSL_CTX* 	ctx;
	SSL_METHOD* meth;

private:
	std::string tunname;
};

void vpnBase::initializeSSL(const char* certificatefile, const char* privatekeyfile, bool isServer)
{
	// SSL library initialization
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	// SSL context initialization
	if (isServer)
		meth = (SSL_METHOD*)SSLv23_server_method();
	else
		meth = (SSL_METHOD*)SSLv23_client_method();

	ctx = SSL_CTX_new(meth);
	//  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);
	// if (isServer) {
	// 	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
	// }

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);

	// Set up the server certificate
	if (SSL_CTX_use_certificate_file(ctx, certificatefile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}

	//Set up the server private key
	if (SSL_CTX_use_PrivateKey_file(ctx, privatekeyfile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}
}


void vpnBase::createTUNDevice()
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	tunfd = open("/dev/net/tun", O_RDWR);
	CHK_ERR(tunfd, "open tun device");

	int ret = ioctl(tunfd, TUNSETIFF, &ifr);
	CHK_ERR(ret, "Setup tun interface by ioctl");

	printf("Setup TUN interface success!\n");
	tunname = ifr.ifr_ifrn.ifrn_name;
	printf("TUNname : %s\n", tunname.c_str());
}

void vpnBase::setupTUNIPaddr(const char* fixedip, const int maskbit)
{
	int ret = 0;
	int movebit = 32 - maskbit;

	assert(movebit >= 0 && movebit < 32);
	uint32_t netmasknum = 0xffffffff;
	netmasknum = ((netmasknum >> movebit) << movebit);
	struct ifreq ifr;
	struct sockaddr_in sockdata, netmask;

	sockdata.sin_family = AF_INET;
	sockdata.sin_addr.s_addr = inet_addr(fixedip);

	// sockdata.sin_addr.s_addr = inet_addr("192.168.53.1");

	printf("tunname : %s\n", tunname.c_str());
	printf("tun fixed ip : %s\n", fixedip);

	netmask.sin_family = AF_INET;
	netmask.sin_addr.s_addr = htonl(netmasknum);

	// netmask.sin_addr.s_addr = inet_addr("255.255.255.0");

	printf("Network ordered netmask : %08x\n", netmask.sin_addr.s_addr);
	/*
	   char name[5] = "tun0"; name[4] = '\0';
	   printf("size : %d\n", tunname.size());
	   memcpy(ifr.ifr_ifrn.ifrn_name, name, 5 * sizeof(char));
	*/

	// especially note the tunname.size() + 1 (Don't know why)
	memcpy(ifr.ifr_ifrn.ifrn_name, tunname.c_str(), (tunname.size() + 1)*sizeof(char));
	memcpy(&ifr.ifr_ifru.ifru_addr, &sockdata, sizeof(sockdata));

	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	ret = ioctl(fd, SIOCSIFADDR, &ifr);
	assert(ret >= 0);


	memset(&ifr.ifr_ifru, 0, sizeof(ifr.ifr_ifru));
	ifr.ifr_flags = (IFF_UP | IFF_POINTOPOINT | IFF_RUNNING | IFF_NOARP | IFF_MULTICAST);
	ioctl(fd, SIOCSIFFLAGS, &ifr);
	assert(ret >= 0);


	memset(&ifr.ifr_ifru, 0, sizeof(ifr.ifr_ifru));
	memcpy(&ifr.ifr_ifru.ifru_netmask, &netmask, sizeof(netmask));

	ioctl(fd, SIOCSIFNETMASK, &ifr);
	assert(ret >= 0);
}


// just for DEBUG

void parseDstaddr(char* buf, int len) {
	assert(len >= 20);
	int idx = 16, size = 3;
	// printf("16~19 : %d %d %d %d\n", (uint8_t)buf[16], (uint8_t)buf[17], (uint8_t)buf[18], (uint8_t)buf[19]);
	std::string ipaddr = std::to_string((uint8_t)buf[idx++]);
	while (size--) {
		ipaddr += ("." + std::to_string((uint8_t)buf[idx++]));
	}
	printf("%s\n", ipaddr.c_str());
}



#endif