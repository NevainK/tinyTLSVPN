#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <assert.h>
#include <thread>
#include <mutex>
#include <queue>
#include <type_traits>
#include <functional>
#include <condition_variable>

using std::function;

class threadpool {

public:
	explicit threadpool(int threadnum = 8) : isStop(false) {
		assert(threadnum > 0);
		for (int i = 0; i < threadnum; i++) {
			std::thread([&] {
				std::unique_lock<std::mutex> ulock(mtx);
				while (!isStop) {
					if (!tasks.empty()) {
						auto task = std::move(tasks.front());
						tasks.pop();
						ulock.unlock();
						task();
						ulock.lock();
					}
					else cv.wait(ulock);
				}
			}).detach();
		}
	}

	~threadpool() {
		{
			std::lock_guard<std::mutex> lock(mtx);
			isStop = true;
		}
		cv.notify_all();
	}

	template<typename F>
	void addTask(F && task) {
		typedef typename std::remove_reference<decltype(task)>::type A;
		static_assert(std::is_class<A>::value, "At least a class");
		{
			std::lock_guard<std::mutex> guard(mtx);
			tasks.emplace(std::forward<F>(task));
		}
		// printf("notice one\n");
		cv.notify_one();
	}
public:
	std::mutex mtx;
	std::condition_variable cv;
	std::queue<function<void()>> tasks;
	bool isStop;
};


#endif