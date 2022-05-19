#include "epoller.h"
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/types.h>


epoller::epoller() : epollfd(epoll_create(1024)), epevents(new epoll_event[10000]) { }

epoller::~epoller() { close(epollfd); delete[] epevents; }

void epoller::addfd(int fd, uint32_t events) {
	assert(fd >= 0);
	epoll_event event = { 0 };
	event.data.fd = fd;
	event.events = events;
	epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event);
}

void epoller::modfd(int fd, uint32_t events) {
	assert(fd >= 0);
	epoll_event event = { 0 };
	event.data.fd = fd;
	event.events = events;
	epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &event);
}

void epoller::delfd(int fd) {
	assert(fd >= 0);
	epoll_event event = { 0 };
	epoll_ctl(fd, EPOLL_CTL_DEL, fd, &event);
}

int epoller::wait(int timeout) {
	return epoll_wait(epollfd, epevents, maxevents, timeout);
}

epoll_event* epoller::getEvents() {
	return epevents;
}