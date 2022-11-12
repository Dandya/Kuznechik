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
testIMITO:
	@g++ -std=c++11 -pthread -I./tests/gtest/include -c -o tests_IMITO.o ./tests/tests_IMITO.cpp
	@g++ -o tests_IMITO.exe tests_IMITO.o -L./tests/gtest/build/lib -lgtest -pthread
	./tests_IMITO.exe
	rm *.o 
testCBC:
	@g++ -std=c++11 -pthread -I./tests/gtest/include -c -o tests_CBC.o ./tests/tests_CBC.cpp
	@g++ -o tests_CBC.exe tests_CBC.o -L./tests/gtest/build/lib -lgtest -pthread
	./tests_CBC.exe
	rm *.o 
testCTR:
	@g++ -std=c++11 -pthread -I./tests/gtest/include -c -o tests_CTR.o ./tests/tests_CTR.cpp
	@g++ -o tests_CTR.exe tests_CTR.o -L./tests/gtest/build/lib -lgtest -pthread
	./tests_CTR.exe
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
testIMITOTable:
	@g++ -std=c++11 -DTABLE_REALIZATION -pthread -I./tests/gtest/include -c -o tests_IMITO.o ./tests/tests_IMITO.cpp
	@g++ -o tests_IMITO.exe tests_IMITO.o -L./tests/gtest/build/lib -lgtest -pthread
	./tests_IMITO.exe
	rm *.o 
testCBCTable:
	@g++ -std=c++11 -DTABLE_REALIZATION -pthread -I./tests/gtest/include -c -o tests_CBC.o ./tests/tests_CBC.cpp
	@g++ -o tests_CBC.exe tests_CBC.o -L./tests/gtest/build/lib -lgtest -pthread
	./tests_CBC.exe
	rm *.o 
testCTRTable:
	@g++ -std=c++11 -DTABLE_REALIZATION -pthread -I./tests/gtest/include -c -o tests_CTR.o ./tests/tests_CTR.cpp
	@g++ -o tests_CTR.exe tests_CTR.o -L./tests/gtest/build/lib -lgtest -pthread
	./tests_CTR`.exe
	rm *.o 