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
#include <inttypes.h>     // printf uint64_t
#include "SHA256.h"
#include "RIPEMD160.h"
#include "SHA512.hpp"
#include "GaloisField.hpp"
using namespace std::chrono;
using namespace sw; // For SHA512.hpp
using namespace std;

struct point
{
	GF x;
	GF y;
};

// Values for secp256k1
class Curve
{
public:
	mpz_class N;
	mpz_class P;
	point G;
	Curve() // Constructor
	{
		mpz_class N("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
		mpz_class P("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
		mpz_class x("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
		mpz_class y("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
		this->G.x = GF(x,P);
		this->G.y = GF(y,P);
		this->N = N;
		this->P = P;
	}
};
Curve secp256k1;

// Addition operation on the elliptic curve
// See: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition
point add(point &p, point &q)
{
	// Calculate lambda
	GF lambda;
	if (p.x == q.x && p.y == q.y)
	{
		lambda = ( p.x.pow(2) * 3 ) / ( p.y * 2 );
	}
	else
	{
		lambda = (q.y - p.y) / (q.x - p.x);
	}

	// Add points
	point r;
	r.x = lambda.pow(2) - p.x - q.x;
	r.y = lambda * (p.x - r.x) - p.y;
	return r;
}

// Convert private key to public
point priv2pub(GF &sk, point *Q=NULL)
{
	// Copy generator
	point G;
	if (Q == NULL)
	{
		G.x = secp256k1.G.x;
		G.y = secp256k1.G.y;	
	}
	else
	{
		G.x = Q->x;
		G.y = Q->y;
	}

	// Pre calculate all multiples of G
	static bool calculated = false;
	static point Gs[256];
	if (!calculated)
	{
		for (int i=0; i<256; i++)
		{
			Gs[i].x = G.x;
			Gs[i].y = G.y;
			G = add(G, G);
		}
		calculated = true;
	}

	// Compute G * sk
	point pub;
	pub.x = GF(0,secp256k1.P);
	pub.y = GF(0,secp256k1.P);
	mpz_class bit;
	bit = 1;
	for (int i=0; i<256; i++)
	{
		mpz_class cmp = 0;
		mpz_and (cmp.get_mpz_t(), bit.get_mpz_t(), sk.getNum().get_mpz_t());
		if (cmp != 0)
		{
			if (pub.x == 0 && pub.y == 0)
			{
				pub.x = Gs[i].x;
				pub.y = Gs[i].y;
			}
			else
			{
				pub = add(pub, Gs[i]);
			}
		}
		bit = bit << 1;
	}
	return pub;
}

// Convert hash to hex string
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
	sprintf(buffer,"%" PRIu64 " years, %" PRIu64 " days, %" PRIu64 " hours, %" PRIu64 " minutes and %" PRIu64 " seconds",y,d,h,m,s);
	return buffer;
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
string mainnetChecksum(string mainnet, const string &key, bool compress)
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

// Encode using Base58Check
string encodeBase58Check(string hex)
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
string sk2wif(const string &hex, bool compress)
{
	string hexCheck = mainnetChecksum("80",hex,compress);
	return encodeBase58Check(hexCheck);
}

// Convert bitcon public address to base58Check
string binary2Addr(const string &str)
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
	mpz_mod(res.get_mpz_t(), pk.y.getNum().get_mpz_t(), mod.get_mpz_t());
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

// Kryptonite main function
void krypt(uint8_t *source, uint8_t *destination, int len, string password)
{
	// Define digestLen to an unexpected value
	int sumPass = 0;
	for (int i=0; i<(int)password.size(); i++)
	{
		sumPass += password[i];
	}
	int digestLen = 32;
	digestLen += sumPass % 32; // Digestlen will vary from 32 to 64 bytes

	// Create digest of password and convert to byte array
	string digestStr = sha512::calculate(password);
	uint8_t digest[64];
	char byte[3];
	unsigned int hex;
	byte[2] = 0;
	for (int i=0; i<128; i+=2)
	{
		byte[0] = digestStr[i];
		byte[1] = digestStr[i+1];
		sscanf(byte,"%x",&hex);
		digest[i/2] = hex;
	}

	// Xor each byte of both digest and source up to digestLen
	// Repeat cropped digest up to income string length
	int count = 0;
	for (int i=0; i<len; i++)
	{
		destination[i] = source[i] ^ digest[count];
		count++;
		if (count == digestLen)
		{
			count = 0;
		}
	}
}	

// Save results
void saveKey(string p, int b, int n, string hex, string wifC, string pubC, string seg, string eta)
{
	// Show found key on stdout
	cout << "Public Key compressed        - " << pubC << endl;
	cout << "Public Segwit P2SH(P2WPKH)   - " << seg  << endl;

	// Create string to be encrypted
	string toEncrypt = "";
	toEncrypt += "Brain Password               - " + p + "\n";
	toEncrypt += "Base                         - " + to_string(b) + "\n";
	toEncrypt += "Exponent                     - " + to_string(n) + "\n";
	toEncrypt += "Private Key (hex)            - " + hex + " - It should be deleted" + "\n";
	toEncrypt += "Private Key (WIF compressed) - " + wifC + " - It should be deleted" + "\n";
	toEncrypt += "Public Key compressed        - " + pubC + "\n";
	toEncrypt += "Public Segwit P2SH(P2WPKH)   - " + seg + "\n";
	toEncrypt += "Time to complete             - " + eta + "\n";

	// Encrypt string
	int length = toEncrypt.size();
	uint8_t *source = new uint8_t[length];
	uint8_t *destination = new uint8_t[length];
	for (int i=0; i<length; i++)
		source[i] = toEncrypt[i];
	krypt(source,destination,length,p);

	// Save key on a file
	string fileName = pubC + ".krypt";
	ofstream file(fileName, ios::out | ios::binary);
	if (!file)
	{
		cout << "Unable to save " << fileName << endl;
		exit(1);
	}
	file.write((char*)destination,length);
	delete [] source;
	delete [] destination;
	file.close();
}

//  ripemd160(sha256(x))
string hash160(const string &x)
{
	return getHash(getHash(x,1),2);
}

int main(int argc, char **argv)
{
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
	interval = limit / 1000;
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
				cout << "Rate: " << rate << " hash/s, Remaining: " << etaStr << endl;
				intern += interval;
			}
		}
	}
	cout << endl;

	// Create Private Key
	string bufStr = hash2str(hashBuf, 32);
	GF sk(mpz_class(bufStr,16),secp256k1.P);

	// Convert private key to WIF (compressed)
	char privBuf[65];
	gmp_sprintf(privBuf, "%Z064x", sk.getNum().get_mpz_t());
	string wifC = sk2wif(privBuf,true);

	// Get Public Key
	point pk = priv2pub(sk);

	// Convert public key to address (compressed)
	char pubBuf[131];
	gmp_sprintf(pubBuf, "04%Z064x%Z064x", pk.x.getNum().get_mpz_t(), pk.y.getNum().get_mpz_t());
	string pubC = binary2Addr(splitXY(pubBuf,pk));

	// Create Segwit P2SH(P2WPKH) address
	string seg = encodeBase58Check(mainnetChecksum("05",hash160("0014"+hash160(splitXY(pubBuf,pk))),false));

	// Show all calculated info
	saveKey(password,b,n,privBuf,wifC,pubC,seg,etaTotal);
}

