all: crypto.exe

crypto.exe:
	@gcc ./src/main.c -DTABLE_REALIZATION -O2 -o crypto.exe

testBase:
	@g++ -std=c++11 -pthread -I./tests/gtest/include -c -o tests_Base.o ./tests/tests_Base.cpp
	@g++ -o tests_Base.exe tests_Base.o -L./tests/gtest/build/lib -lgtest -pthread
	@./tests_Base.exe
	@rm *.o
	@echo "\n"
testECB:
	@g++ -std=c++11 -pthread -I./tests/gtest/include -c -o tests_ECB.o ./tests/tests_ECB.cpp
	@g++ -o tests_ECB.exe tests_ECB.o -L./tests/gtest/build/lib -lgtest -pthread
	@./tests_ECB.exe
	@rm *.o
	@echo "\n"
testIMITO:
	@g++ -std=c++11 -pthread -I./tests/gtest/include -c -o tests_IMITO.o ./tests/tests_IMITO.cpp
	@g++ -o tests_IMITO.exe tests_IMITO.o -L./tests/gtest/build/lib -lgtest -pthread
	@./tests_IMITO.exe
	@rm *.o
	@echo "\n" 
testCBC:
	@g++ -std=c++11 -pthread -I./tests/gtest/include -c -o tests_CBC.o ./tests/tests_CBC.cpp
	@g++ -o tests_CBC.exe tests_CBC.o -L./tests/gtest/build/lib -lgtest -pthread
	@./tests_CBC.exe
	@rm *.o
	@echo "\n" 
testCTR:
	@g++ -std=c++11 -pthread -I./tests/gtest/include -c -o tests_CTR.o ./tests/tests_CTR.cpp
	@g++ -o tests_CTR.exe tests_CTR.o -L./tests/gtest/build/lib -lgtest -pthread
	@./tests_CTR.exe
	@rm *.o 
	@echo "\n" 
testOFB:
	@g++ -std=c++11 -pthread -I./tests/gtest/include -c -o tests_OFB.o ./tests/tests_OFB.cpp
	@g++ -o tests_OFB.exe tests_OFB.o -L./tests/gtest/build/lib -lgtest -pthread
	@./tests_OFB.exe
	@rm *.o 
	@echo "\n" 
testCFB:
	@g++ -std=c++11 -pthread -I./tests/gtest/include -c -o tests_CFB.o ./tests/tests_CFB.cpp
	@g++ -o tests_CFB.exe tests_CFB.o -L./tests/gtest/build/lib -lgtest -pthread
	@./tests_CFB.exe
	@rm *.o 
	@echo "\n" 
testBaseTable:
	@g++ -std=c++11 -DTABLE_REALIZATION -pthread -I./tests/gtest/include -c -o tests_Base.o ./tests/tests_Base.cpp
	@g++ -o tests_Base.exe tests_Base.o -L./tests/gtest/build/lib -lgtest -pthread
	@./tests_Base.exe
	@rm *.o
	@echo "\n" 
testECBTable:
	@g++ -std=c++11 -DTABLE_REALIZATION -pthread -I./tests/gtest/include -c -o tests_ECB.o ./tests/tests_ECB.cpp
	@g++ -o tests_ECB.exe tests_ECB.o -L./tests/gtest/build/lib -lgtest -pthread
	@./tests_ECB.exe
	@rm *.o
	@echo "\n" 
testIMITOTable:
	@g++ -std=c++11 -DTABLE_REALIZATION -pthread -I./tests/gtest/include -c -o tests_IMITO.o ./tests/tests_IMITO.cpp
	@g++ -o tests_IMITO.exe tests_IMITO.o -L./tests/gtest/build/lib -lgtest -pthread
	@./tests_IMITO.exe
	@rm *.o 
	@echo "\n" 
testCBCTable:
	@g++ -std=c++11 -DTABLE_REALIZATION -pthread -I./tests/gtest/include -c -o tests_CBC.o ./tests/tests_CBC.cpp
	@g++ -o tests_CBC.exe tests_CBC.o -L./tests/gtest/build/lib -lgtest -pthread
	@./tests_CBC.exe
	@rm *.o 
	@echo "\n" 
testCTRTable:
	@g++ -std=c++11 -DTABLE_REALIZATION -pthread -I./tests/gtest/include -c -o tests_CTR.o ./tests/tests_CTR.cpp
	@g++ -o tests_CTR.exe tests_CTR.o -L./tests/gtest/build/lib -lgtest -pthread
	@./tests_CTR.exe
	@rm *.o 
	@echo "\n" 
testOFBTable:
	@g++ -std=c++11 -DTABLE_REALIZATION -pthread -I./tests/gtest/include -c -o tests_OFB.o ./tests/tests_OFB.cpp
	@g++ -o tests_OFB.exe tests_OFB.o -L./tests/gtest/build/lib -lgtest -pthread
	@./tests_OFB.exe
	@rm *.o 
	@echo "\n" 
testCFBTable:
	@g++ -std=c++11 -DTABLE_REALIZATION -pthread -I./tests/gtest/include -c -o tests_CFB.o ./tests/tests_CFB.cpp
	@g++ -o tests_CFB.exe tests_CFB.o -L./tests/gtest/build/lib -lgtest -pthread
	@./tests_CFB.exe
	@rm *.o 
	@echo "\n" 
testSHA256:
	@g++ -std=c++11 -pthread -I./tests/gtest/include -c -o tests_SHA256.o ./tests/tests_SHA256.cpp
	@g++ -o tests_SHA256.exe tests_SHA256.o -L./tests/gtest/build/lib -lgtest -pthread
	@./tests_SHA256.exe
	@rm *.o 
	@echo "\n" 
testAll:
	make testBase testECB testIMITO testCBC testCTR testOFB testCFB testSHA256
testAllTable:
	make testBaseTable testECBTable testIMITOTable testCBCTable testCTRTable testOFBTable testCFBTable testSHA256