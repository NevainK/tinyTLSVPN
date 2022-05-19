SRCS := ./src/include/*
TARGETDOCKERHOST := HostU userA

all:
	@g++ -o tcpvpnclient ./src/vpnclient.cpp $(SRCS) -lssl -lcrypto -lpthread -std=c++14
	@g++ -o tcpvpnserver ./src/vpnserver.cpp $(SRCS) -lssl -lcrypto -lpthread -std=c++14
#	@rm tcpvpnclient

run: all
	@./copy.sh $(TARGETDOCKERHOST)
	@./start.sh

debug:	
	g++ -o tcpvpnclient ./src/vpnclient.cpp $(SRCS) -lssl -lcrypto -lpthread -std=c++14 -g
	g++ -o tcpvpnserver ./src/vpnserver.cpp $(SRCS) -lssl -lcrypto -lpthread -std=c++14 -g

clean: 
	rm -f tcpvpnserver tcpvpnclient

