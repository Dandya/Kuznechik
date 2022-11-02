test:
	g++ -std=c++11 -pthread -I./tests/gtest/include -c -o tests.o ./tests/tests.cpp
	g++ -o tests.exe tests.o -L./tests/gtest/build/lib -lgtest -pthread
	./tests.exe
	rm *.o