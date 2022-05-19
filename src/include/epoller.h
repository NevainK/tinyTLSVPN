#ifndef EPOLLER_H
#define EPOLLER_H

#include <errno.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

const uint32_t ConnIn = (EPOLLRDHUP | EPOLLIN | EPOLLONESHOT);


class epoller {

public:
	const int maxevents = 10000;
	epoller();
	~epoller();
	void addfd(int fd, uint32_t events);
	void modfd(int fd, uint32_t events);
	void delfd(int fd);
	int  wait(int timeout = -1);
	epoll_event* getEvents();
private:
	int epollfd;
	epoll_event* epevents;
};


#endif