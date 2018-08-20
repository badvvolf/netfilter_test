all : netfilter_test

netfilter_test: netfilter_test.o 
	g++ -g -o netfilter_test netfilter_test.o -lnetfilter_queue

netfilter_test.o:
	g++ -g -c -o netfilter_test.o netfilter_test.cpp

clean:
	rm -f netfilter_test
	rm -f *.o

