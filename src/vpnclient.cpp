#include "include/vpnclient.h"

int main(int argc, char* argv[])
{
	daemon(1, 1);
	assert(argc == 2);
	vpnclient client(argv[1]);
	client.start();
}