CXX=$(shell which clang++ g++ c++ 2>/dev/null | head -n 1)
INCLUDES?=-Iext/libzt/ext/ZeroTierOne/osdep

release:
	git submodule update --init
	git -C ext/libzt submodule update --init
	-cp libzt.patch ext/libzt
	-git -C ext/libzt apply --reject libzt.patch
	cd ext/libzt && ./build.sh host "release"
	clang++ -Wno-deprecated pylon.c -o pylon ext/libzt/dist/*-host-release/lib/libzt.a -Iext/libzt/include

debug:
	git submodule update --init
	git -C ext/libzt submodule update --init
	-cp libzt.patch ext/libzt
	-git -C ext/libzt apply --reject libzt.patch
	cd ext/libzt && ./build.sh host "debug"
	clang++ -DPYLON_DEBUG=1 -g -Wno-deprecated pylon.c -o pylon-debug ext/libzt/dist/*-host-debug/lib/libzt.a -Iext/libzt/include -fsanitize=address -DASAN_OPTIONS=symbolize=1

relay:
	$(CXX) -O3 -fno-rtti $(INCLUDES) -std=c++11 -frtti  -o tcp-proxy tcp-proxy.cpp

clean:
	rm -rf pylon pylon-*
	rm -f *.o tcp-proxy *.dSYM

fmt:
	clang-format -i pylon.c -style file