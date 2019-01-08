SRC=test-main.cpp ./xxhash.c
BIN=cdc
BIN_AVX=cdc-avx
Debug_Bin=cdc.debug
FLAGS= -lbsd -lpthread

all:
	gcc $(FLAGS) -O3 -o $(BIN) $(SRC) -lssl -lcrypto $(FLAGS)
	gcc $(FLAGS) -g -o $(Debug_Bin) $(SRC) -lssl -lcrypto $(FLAGS)
	#gcc $(FLAGS) -O3 -march=native -o $(BIN_AVX) $(SRC) -lssl -lcrypto $(FLAGS)
clean:
	rm -f $(BIN) $(Debug_Bin) $(BIN_AVX)
