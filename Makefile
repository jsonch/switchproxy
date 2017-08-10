simpleproxy: simpleproxy.cpp
	g++ -o simpleproxy simpleproxy.cpp -std=c++11 -lpthread

clean:
	rm simpleproxy