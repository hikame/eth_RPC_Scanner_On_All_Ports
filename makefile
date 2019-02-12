rpc_scanner: ./rpc_scanner.cc
	clang++ -Wall -std=c++11 -pthread -I./rapidjson/include/rapidjson -lcurl -lsqlite3 ./rpc_scanner.cc -g -O0 -o rpc_scanner

clean:
	rm rpc_scanner