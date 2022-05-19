#include "include/vpnserver.h"

int main()
{
	daemon(1, 1);
	vpnserver server;
	server.start();
}