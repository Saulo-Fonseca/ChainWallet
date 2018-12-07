// Title: ChainWallet
// Author: Saulo Fonseca <fonseca@astrotown.de>
// Description: Generate a ChainWallet by key stretching you private key
// Dependencies: You need to install GMP library

#include <stdlib.h> // srand()
#include <iomanip>  // time()
#include <gmpxx.h>  // mpz_class (bignum)
#include <iostream>
#include <string>
#include <chrono>
#include <fstream>
#include "SHA256.h"
#include "RIPEMD160.h"
using namespace std::chrono;
using namespace std;

struct point
{
	mpz_class x;
	mpz_class y;
};

// Convert hash to string
string hash2str(uint8_t *hash, int len)
{
	char buf[3];
	string bufStr;
	for (int i=0; i<len; i++)
	{
		sprintf(buf, "%02x", hash[i]);
		bufStr += buf;
	}
	return bufStr;
}

// Convert to human time
string toYDHMS(uint64_t s)
{
	char buffer[1000];
	uint64_t m = s / 60;
	s -= m*60;
	uint64_t h = m / 60;
	m -= h*60;
	uint64_t d = h / 24;
	h -= d*24;
	uint64_t y = d / 365;
	d -= y*365;
	sprintf(buffer,"%llu years, %llu days, %llu hours, %llu minutes and %llu seconds",y,d,h,m,s);
	return buffer;
}

// Creates a random number with 256 bits
void genPriv(mpz_class &sk)
{
	// 1 < sk < N -1
	static mpz_class N("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
	do
	{
		sk = 0;
		for (int i=0; i<32; i++)
		{
			sk = sk << 8;
			sk += rand()%256;
		}
	} while (sk <= 0 || sk >= N);
}

// Addition operation on the elliptic curve
// See: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition
void add(point &p, point &q)
{
	// Define Prime
	// 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
	static mpz_class P("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
	static mpz_class lam;
	static mpz_class mod = 0;
	static mpz_class P2 = P - 2;
	
	// Calculate lambda
	if (p.x == q.x && p.y == q.y)
	{
		mpz_class opr = 2 * p.y;
		mpz_powm(mod.get_mpz_t(), opr.get_mpz_t(), P2.get_mpz_t(), P.get_mpz_t());
		lam = (3 * p.x * p.x) * mod;
	}
	else
	{
		mpz_class opr = q.x - p.x;
		mpz_powm(mod.get_mpz_t(), opr.get_mpz_t(), P2.get_mpz_t(), P.get_mpz_t());
		lam = (q.y - p.y) * mod;
	}

	// Add points
	static point r;
	r.x = lam*lam - p.x - q.x;
	r.y = lam * (p.x - r.x) - p.y;
	mpz_mod(p.x.get_mpz_t(), r.x.get_mpz_t(), P.get_mpz_t());
	mpz_mod(p.y.get_mpz_t(), r.y.get_mpz_t(), P.get_mpz_t());
}

// Convert private key to public
void priv2pub(mpz_class &sk, point &pub)
{
	// Define Base Point (G point)
	static mpz_class x("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
	static mpz_class y("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
	static point G;
	G.x = x;
	G.y = y;

	// Compute G * sk with repeated addition.
	// By using the binary representation of ski, this
	// ca be done in 256 iterations (double-and-add)
	pub.x = 0;
	pub.y = 0;
	static mpz_class bit;
	bit = 1;
	for (int i=0; i<256; i++)
	{
		mpz_class cmp = 0;
		mpz_and (cmp.get_mpz_t(), bit.get_mpz_t(), sk.get_mpz_t());
		if (cmp != 0)
		{
			if (pub.x == 0 && pub.y == 0)
			{
				pub.x = G.x;
				pub.y = G.y;
			}
			else
			{
				add(pub, G);
			}
		}
		add(G, G);
		bit = bit << 1;
	}
}

// Interface to external hash libraries
// function = 1, hash = SHA-256
// function = 2, hash = RIPEMP160
string getHash(string str, int function)
{
	// Convert string to uint8_t array
	int length = str.length() / 2;
	uint8_t *source = new uint8_t[length];
	for (int i=0; i<(int)str.length(); i+=2)
		source[i/2] = stoul(str.substr(i,2),nullptr,16);

	// Get hash of array
	int lenHash = 32;
	if (function == 2)
		lenHash = 20;
	uint8_t *hashBuf =  new uint8_t[lenHash];
	if (function == 1)
		computeSHA256(source, length, hashBuf);
	else if (function == 2)
		computeRIPEMD160(source, length, hashBuf);

	// Convert back to string
	string ret = hash2str(hashBuf, lenHash);
	delete [] source;
	delete [] hashBuf;
	return ret;
}

// Add mainnet address and checksum
string mainnetChecksum(string mainnet, string key, bool compress)
{
	// mainnet  = 0x80 for private key and 0x00 for public key
	// key      = Hex with 32 bytes for private key and 20 for ripemd160 of public key
	// compress = If defined, generate the compressed form for private key
	mainnet += key;
	if (compress)
		mainnet += "01";
	string sha = getHash(getHash(mainnet,1),1); // sha256(sha256(x))
	string checksum = sha.substr(0,8);
	string newKey = mainnet+checksum;
	return newKey;
}

// Encode using Base58Check encoding
string encodeBase58Check(string &hex)
{
	// Define scope
	static string base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	// Find multiple rest of division by 58
	mpz_class dec(hex.c_str(), 16);
	static mpz_class mod = 58;
	string output = "";
	while (dec>0)
	{
		mpz_class remainder;
		mpz_mod(remainder.get_mpz_t(), dec.get_mpz_t(), mod.get_mpz_t());
		dec = (dec - remainder) / 58;
		output = base58[(int)remainder.get_ui()] + output;
 	}

	// Replace all leading zeros by 1
	while (hex.substr(0,2) == "00")
	{
		output = "1" + output;
		hex = hex.substr(2);
	}
	return output;
}

// Create Private Key Wallet Import Format (WIF)
string sk2wif(string hex, bool compress)
{
	string hexCheck = mainnetChecksum("80",hex,compress);
	return encodeBase58Check(hexCheck);
}

// Convert bitcon public address to base58Check
string binary2Addr(string str)
{
	// Empty argument generate key for 1HT7xU2Ngenf7D4yocz2SAcnNLW7rK8d4E with almost 70 bitcoins
	string sha = getHash(str,1);
	string hexCheck = mainnetChecksum("00",getHash(sha,2),0); // ripemd160(sha256(x))
	return encodeBase58Check(hexCheck);
}

// Split X and Y values from public key
string splitXY(string key, point &pk)
{
	string x = key.substr(2,64);
	static mpz_class res;
	static mpz_class mod = 2;
	mpz_mod(res.get_mpz_t(), pk.y.get_mpz_t(), mod.get_mpz_t());
	if (res == 0)
		return "02" + x;
	return "03" + x;
}

// Hide shown parameters
void removePwd()
{
	for (int i=0; i<4; i++)
	{
        printf("\033[1A"); // Move 1 line up
        printf("\033[K");  // Erase line
	}
}

// Save results
void saveKey(string p, int b, int n, string hex, string wifC, string pubC, string eta)
{
	// Show found key on stdout
	cout << "Public Key compressed        - " << pubC << endl;

	// Save key on a file
	string fileName = pubC + ".txt";
	ofstream file(fileName);
	if (!file)
	{
		cout << "Unable to save " << fileName << endl;
		exit(1);
	}
	file << "Brain Password               - " << p << endl;
	file << "Base                         - " << b << endl;
	file << "Exponent                     - " << n << endl;
	file << "Private Key (hex)            - " << hex << " - It should be deleted" << endl;
	file << "Private Key (WIF compressed) - " << wifC << " - It should be deleted" << endl;
	file << "Public Key compressed        - " << pubC << endl;
	file << "Time to complete             - " << eta << endl;
	file.close();
}


int main(int argc, char **argv)
{
	srand((int)time(NULL));

	// Ask parameters
	string password;
	int n, b;
	char p;
	cout << "Type your brain wallet password: ";
	getline(cin,password);
	cout << "Type the base of chain length (B^N). B = ";
	cin >> b;
	cout << "Type the exponent of chain length (" << b << "^N). N = ";
	cin >> n;
	cout << "Print intermediary hash values (y/n) ? ";
	cin >> p;
	removePwd();

	// Get sha256 of password
	int length = password.length();
	uint8_t *source = new uint8_t[length];
	for (int i=0; i<length; i++)
		source[i] = password[i];
	uint8_t hashBuf[32];
	computeSHA256(source, length, hashBuf);
	delete [] source;

	// Define variables for loop
	string etaStr, etaTotal;
	mpz_class limit, j, interval, intern;
	auto start = high_resolution_clock::now();
	uint8_t src[32];

	// Calculate exponent
	mpz_ui_pow_ui (limit.get_mpz_t(), b, n);
	interval = limit / 100;
	intern = interval;

	// Run chain loop
	cout << endl << "Generating sha256(sha256(sha256(...sha256(password)...)))" << endl;
	cout << "If N is big, it will take a long time" << endl << endl;;
	if (p == 'y' or p == 'Y')
		cout << hash2str(hashBuf, 32) << endl;
	for (j=0; j<limit-1; j++)
	{
		for (int i=0; i<32; i++)
			src[i] = hashBuf[i];
		computeSHA256(src, 32, hashBuf);
		if (p == 'y' or p == 'Y')
			cout << hash2str(hashBuf, 32) << endl;
		if (j == 1000000 || (j>1000000 && j == intern))
		{
			auto end = high_resolution_clock::now();
			auto elapsed = duration_cast<milliseconds>(end-start).count();
			if (elapsed > 0) // For the case you can process more than 1Gh
			{
				double rate = j.get_ui()*1000/elapsed;
				mpz_class eta = (limit-j) / rate;
				mpz_class etaEnd = limit / rate;
				etaStr = toYDHMS(eta.get_ui());
				etaTotal = toYDHMS(etaEnd.get_ui());
				cout << "Remaining: " << etaStr << endl;
				intern += interval;
			}
		}
	}
	cout << endl;

	// Create Private Key
	string bufStr = hash2str(hashBuf, 32);
	mpz_class sk(bufStr, 16);

	// Convert private key to WIF (compressed)
	char privBuf[65];
	gmp_sprintf(privBuf, "%Z064x", sk.get_mpz_t());
	string wifC = sk2wif(privBuf,true);

	// Get Public Key
	point pk;
	priv2pub(sk,pk);

	// Convert public key to address (compressed)
	char pubBuf[131];
	gmp_sprintf(pubBuf, "04%Z064x%Z064x", pk.x.get_mpz_t(), pk.y.get_mpz_t());
	string pubC = binary2Addr(splitXY(pubBuf,pk));

	// Show all calculated info
	saveKey(password,b,n,privBuf,wifC,pubC,etaTotal);
}

