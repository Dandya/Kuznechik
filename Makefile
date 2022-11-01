test:
	g++ -std=c++11 -pthread -I./gtest/include -c -o tests.o tests.cpp
	g++ -o tests tests.o -L./gtest/build/lib -lgtest -pthread
	./tests