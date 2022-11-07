testBase:
	@g++ -std=c++11 -pthread -I./tests/gtest/include -c -o tests_Base.o ./tests/tests_Base.cpp
	@g++ -o tests_Base.exe tests_Base.o -L./tests/gtest/build/lib -lgtest -pthread
	./tests_Base.exe
	rm *.o
testECB:
	@g++ -std=c++11 -pthread -I./tests/gtest/include -c -o tests_ECB.o ./tests/tests_ECB.cpp
	@g++ -o tests_ECB.exe tests_ECB.o -L./tests/gtest/build/lib -lgtest -pthread
	./tests_ECB.exe
	rm *.o 
testBaseTable:
	@g++ -std=c++11 -DTABLE_REALIZATION -pthread -I./tests/gtest/include -c -o tests_Base.o ./tests/tests_Base.cpp
	@g++ -o tests_Base.exe tests_Base.o -L./tests/gtest/build/lib -lgtest -pthread
	./tests_Base.exe
	rm *.o
testECBTable:
	@g++ -std=c++11 -DTABLE_REALIZATION -pthread -I./tests/gtest/include -c -o tests_ECB.o ./tests/tests_ECB.cpp
	@g++ -o tests_ECB.exe tests_ECB.o -L./tests/gtest/build/lib -lgtest -pthread
	./tests_ECB.exe
	rm *.o