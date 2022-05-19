#ifndef IPGENERATOR_H
#define IPGENERATOR_H

#include <vector>
#include <algorithm>

// static const int defaultmask = 21;
extern const int defaultmask;
// avoid usage of x.x.x.0 or x.x.x.ff
const int number = (1 << (24 - defaultmask)) * 254;

// const uint32_t baseip = 0xc0a83001;         //  192.168.48.1
const uint32_t maxipaddr = 0xc0a837ff;         // 192.168.55.255

class TunnelIPGenerator {
public:
	TunnelIPGenerator();
	~TunnelIPGenerator() = default;
	uint32_t getIPfromPool();
	void releaseIP(uint32_t ipaddr);

private:
	std::vector<uint32_t> pool;
};

TunnelIPGenerator::TunnelIPGenerator()
{
	uint32_t baseip = maxipaddr - 1;         // 192.168.55.255(replace by 254)
	pool.resize(number);
	// except first 0xff , other 0x00 correlate with 0xff, thus only judge 0
	std::generate(pool.begin(), pool.end(), [&baseip] {
		return (((baseip & 0x000000ff) == 0)) ? (baseip -= 3) : baseip--;
	});
}

uint32_t TunnelIPGenerator::getIPfromPool() {
	if (pool.empty()) {
		return 0;
	} else {
		uint32_t ret = pool.back();
		pool.pop_back();
		return ret;
	}
}

void TunnelIPGenerator::releaseIP(uint32_t ipaddr) {
	pool.push_back(ipaddr);
}

#endif