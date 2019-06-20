ChainWallet:	*.cpp *.h *.hpp
	g++ -I. -Wall -std=c++11 -lgmpxx -lgmp *.cpp -o ChainWallet
