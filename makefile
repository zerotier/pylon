CXX=$(shell which clang++ g++ c++ 2>/dev/null | head -n 1)
INCLUDES?=-Iext/libzt/ext/ZeroTierOne/osdep -Iext/libzt/ext/ZeroTierOne/ext/prometheus-cpp-lite-1.0/core/include -Iext/libzt/ext/ZeroTierOne/ext-prometheus-cpp-lite-1.0/3rdparty/http-client-lite/include -Iext/libzt/ext/ZeroTierOne/ext/prometheus-cpp-lite-1.0/simpleapi/include


release:
	git submodule update --init
	git -C ext/libzt submodule update --init
	cd ext/libzt && ./build.sh host "release"
	$(CXX) -O3 $(INCLUDES) -Wno-deprecated -std=c++11 pylon.cpp -o pylon ext/libzt/dist/*-host-release/lib/libzt.a -Iext/libzt/include

debug:
	git submodule update --init
	git -C ext/libzt submodule update --init
	cd ext/libzt && ./build.sh host "debug"
	$(CXX) -O3 $(INCLUDES) -DPYLON_DEBUG=1 -g -Wno-deprecated -std=c++11 pylon.cpp -o pylon-debug ext/libzt/dist/*-host-debug/lib/libzt.a -Iext/libzt/include
	#-fsanitize=address -DASAN_OPTIONS=symbolize=1

clean:
	rm -rf pylon pylon-*
	rm -f *.o tcp-proxy *.dSYM

fmt:
	clang-format -i pylon.cpp -style file
