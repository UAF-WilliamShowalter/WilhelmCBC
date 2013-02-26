/*
 Written by William Showalter. williamshowalter@gmail.com.
 Date Last Modified: 2013 February 23
 Created: 2013 February 23

 Released under Creative Commons - creativecommons.org/licenses/by-nc-sa/3.0/
 Attribution-NonCommercial-ShareAlike 3.0 Unported (CC BY-NC-SA 3.0)

 **NOTE**
 I am not a crytologist/cryptanalyst and this software has not been heavily analyzed for security,
 so you should use it to protect actual sensitive data.

 Software is provided as is with no guarantees.


 Source for WilhelmCBC class
 */

#include "WilhelmCBC.h"

#include <stdexcept>	// setInput may throw
#include <iostream>		// Debugging

extern SHA256::digest SHA256_digest (const std::string &src);

// Public Methods
void WilhelmCBC::setInput (std::string filename)
{
	// Open data file
    _ifile.open (filename.c_str(), std::ios::in | std::ios::binary);
    if (!_ifile.is_open())
        throw (std::runtime_error("Could not open input file. Check that directory path is valid."));

	// Find length of data file
    _ifile.seekg(0, std::ios::end);
    _inputSize = _ifile.tellg();
    _ifile.clear();
    _ifile.seekg(0, std::ios::beg);
}

void WilhelmCBC::setOutput (std::string filename)
{
	// Open output file
    _ofile.open (filename.c_str(), std::ios::out | std::ios::binary);
    if (!_ofile.is_open())
        throw (std::runtime_error("Could not open output file. Check that directory path is valid."));

}

void WilhelmCBC::setKey (std::string password)
{
	// Generate 256 bit key from password
	SHA256::digest initKey = SHA256_digest (password);

	for (unsigned int i = 0; i < BLOCK_BYTES; i++)
	{
		_baseKey.data[i] = initKey.data[i];
	}

	/* For Debugging
	for (int i = 0; i < BLOCK_BYTES; i++)
	{
		std::cout << std::hex << (int) initKey.data[i];
	}
	std::cout << std::endl;
	 */

	// Hash key block 5 more times
	for (int i = 0; i < HASHING_REPEATS; i++)
		Hash_SHA256_Block(_baseKey);
}

bool WilhelmCBC::encrypt ()
{
	
}

bool WilhelmCBC::decrypt ()
{
	
}

// Private Methods
void WilhelmCBC::encCBC()
{
	
}
void WilhelmCBC::decCBC()
{
	
}
void WilhelmCBC::blockEnc()
{
	
}
void WilhelmCBC::blockDec()
{
	
}
void WilhelmCBC::roundEnc()
{
	
}
void WilhelmCBC::roundDec()
{
	
}

WilhelmCBC::LRSide WilhelmCBC::fiestel (WilhelmCBC::LRSide)
{
	
}

WilhelmCBC::LRSide WilhelmCBC::permutationKey (WilhelmCBC::Block key, unsigned int round, unsigned int blockNum)
{

	// Generate permutation key from Block key
	key.data[0]+=blockNum;
	Hash_SHA256_Block(key);
	key.data[0]+=round;
	Hash_SHA256_Block(key);

	uint64_t * LRKeyPtr1;

	// XOR the first 128 bits with the second 128 bits.
	LRKeyPtr1 = (uint64_t*)(&key.data[0]);
	LRKeyPtr1[0] = LRKeyPtr1[0]^LRKeyPtr1[2];
	LRKeyPtr1[1] = LRKeyPtr1[1]^LRKeyPtr1[3];

	// return our LRSide key
	return *((LRSide*)LRKeyPtr1);
}

WilhelmCBC::Block WilhelmCBC::IVGenerator ()
{
	// Build IV from system random data;
	Block b;
	std::ifstream random;
	random.open ("/dev/random", std::ios::in | std::ios::binary);
	random.read((char*)&b.data[0],BLOCK_BYTES);
	random.close();

	// Hash random data multiple times
	for (unsigned int i = 0; i < HASHING_REPEATS; i++)
		Hash_SHA256_Block (b);

	// Return our new Block
	return b;
}

WilhelmCBC::Block WilhelmCBC::Padding (WilhelmCBC::Block b)
{
	// We're inserting the number of meaningful (non-padded) bytes of the last data block into some random (but predictable if we know the plaintext!) location in a randomly generated block.
	
	Hash_SHA256_Block(b);
	unsigned int pos = b.data[0] % BLOCK_BYTES;

	Block paddingCounted = IVGenerator();
	
	// Inserting the number of bytes
	paddingCounted.data[pos] = (char)(_inputSize % BLOCK_BYTES);

	return paddingCounted;
}

// Hash 1 block with SHA256. Writes directly to parameter block.
void WilhelmCBC::Hash_SHA256_Block (WilhelmCBC::Block & b)
{
	SHA256 hash;
	hash.add(&b.data[0],BLOCK_BYTES);
	SHA256::digest d = hash.finish();
	
	for (unsigned int i = 0; i < BLOCK_BYTES; i++)
	{
		b.data[i] = d.data[i];
	}

	// For debugging
	// printBlock (b);
}


/**** Overloaded Operators ****/

// Block addition operator
WilhelmCBC::Block & WilhelmCBC::Block::operator+= (const WilhelmCBC::Block &rhs)
{
	// Addition, done in 64bit blocks - no carry between 64bit blocks.
	// Not true addition, but sufficient for key permutation
	uint64_t * dataPtr = (uint64_t*)&data[0];
	const uint64_t * rhsDataPtr = (uint64_t*)&rhs.data[0];
	
	for (unsigned int i = 0; i < BLOCK_BYTES/8; i++)
	{
			dataPtr[i] += rhsDataPtr[i];
	}

	return *this;
}

// For debugging
void	WilhelmCBC::printBlock (WilhelmCBC::Block & b)
{
	for (unsigned int i = 0; i < BLOCK_BYTES; i++)
	{
		std::cout << std::hex << (int)b.data[i];
	}
	std::cout << std::endl;
}

void	WilhelmCBC::printLRSide (WilhelmCBC::LRSide& lr)
{
	for (unsigned int i = 0; i < BLOCK_BYTES/2; i++)
	{
		std::cout << std::hex << (int)lr.data[i];
	}
	std::cout << std::endl;
}

// Debugging

void WilhelmCBC::publicDebugFunc()
{
	Block b = IVGenerator();
	printBlock(b);

	LRSide L = permutationKey(b, 5, 4824);

	Block * ptr = (Block*) (&L);

	printBlock(*ptr);

	printLRSide(L);
}