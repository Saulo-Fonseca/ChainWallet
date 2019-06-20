#ifndef GUARD_GF
#define GUARD_GF

// Class to simulate a Galois Field
// Author: Saulo Fonseca <fonseca@astrotown.de>
#include <gmpxx.h>  // mpz_class (bignum)
#include <stdio.h>
#include <iostream>
#include <string>
#include <exception>
#include <sstream>
using namespace std;

class GF
{
private:
	mpz_class num;
	mpz_class prime;

	// Exit if error
	void abort(const string &msg)
	{
		cout << msg << endl;
		throw std::exception();
	}
	
public:
	// Empty constructor
	GF () {}

	// Constructor
	GF (mpz_class n, mpz_class p)
	{
		mpz_mod(num.get_mpz_t(), n.get_mpz_t(), p.get_mpz_t());
		prime = p;
	}

	// Copy constructor
	GF (const GF &e)
	{
		num = e.num;
		prime = e.prime;
	}

	// Return string
	string toStr(int base=16)
	{
		char buffer[256]; // Max number of digits for printed number
		FILE *stream;
		stream = fmemopen(buffer,256,"w"); 
		mpz_class P("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16);
		mpz_class N("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",16);
		mpz_out_str(stream,base,num.get_mpz_t());
		if (prime == P)
		{
			fprintf(stream," (mod P)");
		}
		else if (prime == N)
		{
			fprintf(stream," (mod N)");
		}
		else
		{
			fprintf(stream," (mod ");
			mpz_out_str(stream,base,prime.get_mpz_t());
			fprintf(stream,")");
		}
		fflush(stream);
		return buffer;
	}

	// Return num
	mpz_class getNum()
	{
		return num;
	}

	// Return prime
	mpz_class getPrime()
	{
		return prime;
	}

	// Check if equal
	bool operator==(const GF &other)
	{
		return num == other.num and prime == other.prime;
	}

	// Check if equal with int
	bool operator==(int n)
	{
		mpz_class m = n;
		return GF(num,prime) == GF(m,prime);
	}

	// Check if not equal
	bool operator!=(GF other)
	{
		return num != other.num or prime != other.prime;
	}

	// Check if not equal with int
	bool operator!=(int n)
	{
		mpz_class m = n;
		return GF(num,prime) != GF(m,prime);
	}

	// Define addition
	GF operator+(GF other)
	{
		if (prime != other.prime)
			abort("Cannot add two numbers in different Fields");
		mpz_class n = num + other.num;
		mpz_mod(n.get_mpz_t(), n.get_mpz_t(), prime.get_mpz_t());
		return GF(n,prime);
	}

	// Define addition with int
	GF operator+(int n)
	{
		mpz_class m = n;
		return GF(num,prime) + GF(m,prime);
	}

	// Define positive number
	GF operator+()
	{
		return GF(num,prime);
	}

	// Define subtraction
	GF operator-(GF other)
	{
		if (prime != other.prime)
			abort("Cannot subtract two numbers in different Fields");
		mpz_class n = num - other.num;
		mpz_mod(n.get_mpz_t(), n.get_mpz_t(), prime.get_mpz_t());
		return GF(n,prime);
	}

	// Define subtraction with int
	GF operator-(int n)
	{
		mpz_class m = n;
		return GF(num,prime) - GF(m,prime);
	}

	// Define negative number
	GF operator-()
	{
		return GF(-num,prime);
	}

	// Define multiplication
	GF operator*(GF other)
	{
		if (prime != other.prime)
			abort("Cannot multiply two numbers in different Fields");
		mpz_class n = num * other.num;
		mpz_mod(n.get_mpz_t(), n.get_mpz_t(), prime.get_mpz_t());
		return GF(n,prime);
	}

	// Define multiplication with int
	GF operator*(int n)
	{
		mpz_class m = n;
		return GF(num,prime) * GF(m,prime);
	}

	// Define exponentiation
	GF pow(mpz_class exp)
	{
		// Adjust exponent to also takes care of negative values
		mpz_class p1 = prime - 1;
		mpz_class e;
		mpz_mod(e.get_mpz_t(), exp.get_mpz_t(), p1.get_mpz_t());

		// Calculate the exponentiation
		mpz_class n;
		mpz_powm(n.get_mpz_t(), num.get_mpz_t(), e.get_mpz_t(), prime.get_mpz_t());
		return GF(n,prime);
	}

	// Define exponentiation with int
	GF pow(int n)
	{
		mpz_class m = n;
		return GF(num,prime).pow(m);
	}

	// Define division
	GF operator/(GF other)
	{
		if (prime != other.prime)
			abort("Cannot divide two numbers in different Fields");
		return GF(num,prime) * other.pow(prime-2);
	}

	// Define division with int
	GF operator/(int n)
	{
		mpz_class m = n;
		return GF(num,prime) / GF(m,prime);
	}

	// Define module
	GF operator%(GF other)
	{
		if (prime != other.prime)
			abort("Cannot get module from two numbers in different Fields");
		mpz_class n;
		mpz_mod(n.get_mpz_t(), num.get_mpz_t(), other.num.get_mpz_t());
		return GF(n,prime);
	}

	// Define module with int
	GF operator%(int n)
	{
		mpz_class m = n;
		return GF(num,prime) % GF(m,prime);
	}
};
#endif

