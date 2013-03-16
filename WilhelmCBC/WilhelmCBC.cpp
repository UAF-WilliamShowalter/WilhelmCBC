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
#include <iomanip>		// Debugging

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
	while (_indexToStream <= _inputSize)
	{
		
	}
}

bool WilhelmCBC::decrypt ()
{
	
}

// Private Methods
void WilhelmCBC::encCBC()
{
	// finds number of blocks to be processed in for loop below. Does not process any trailing unfull blocks (blocks with padding).
	unsigned long relativeBlockCount = _currentBlockSet.size()/BLOCK_BYTES;

	_currentBlock = (Block*)&_currentBlockSet[0];
	
	for (; _currentBlock != (Block*)&_currentBlockSet[0]+relativeBlockCount; ++_currentBlock, ++_blockNum)
	{
		blockEnc();
	}

	// If on last block of file
	if (_currentBlockSet.size()+_indexToStream >= _inputSize)
	{
		// Insert padding block after padded block
		_currentBlockSet.resize(_currentBlockSet.size()+BLOCK_BYTES);
		*(_currentBlock+1) = Padding(*_currentBlock);
		encCBC();

		// Encrypt padded block. This isn't an actual data block, so _blockNum doesn't get incremented.
		//	This has the slight insecurity of the same permutation keys being generated and used on both
		//	the padded block and the padding block. But all but one byte of the padding block is pseudo random.
		++_currentBlock;
		encCBC();
	}
}

void WilhelmCBC::decCBC()
{
	// finds number of blocks to be processed in for loop below. Any correct encrypted file is a multple of BLOCK_BYTES.
	unsigned long relativeBlockCount = _currentBlockSet.size()/BLOCK_BYTES;

	_currentBlock = (Block*)&_currentBlockSet[0];

	for (; _currentBlock != (Block*)&_currentBlockSet[0]+relativeBlockCount; ++_currentBlock, ++_blockNum)
	{
		blockDec();
	}

	// If on last block of file
	if (_currentBlockSet.size()+_indexToStream >= _inputSize)
	{
		Block * paddingBlock = --_currentBlock;

		// Extract obfuscated location of number of meaningful bits, modify inputSize to be the size of unencrypted input
			// Less the padding block, less the padded block, more the number of meaningful bytes in last block.
		_inputSize += paddingBlock->data[(--_currentBlock)->data[0]] - BLOCK_BYTES - BLOCK_BYTES;

		// Removing padding before write out to file
		_currentBlockSet.resize(_currentBlockSet.size()-BLOCK_BYTES);
	}
}

void WilhelmCBC::blockEnc()
{
	_currentL = (LRSide *)_currentBlock;
	_currentR = &_currentL[1];

	for (_roundNum = 0; _roundNum < FIESTEL_ROUNDS; _roundNum++)
		roundEnc();
}

void WilhelmCBC::blockDec()
{
	_currentL = (LRSide *)_currentBlock;
	_currentR = &_currentL[1];

	for (_roundNum = 0; _roundNum < FIESTEL_ROUNDS; _roundNum++)
		roundDec();
}

void WilhelmCBC::roundEnc()
{
	*_currentL = *_currentL ^ fiestel(*_currentR);
	*_currentR = *_currentR ^ fiestel(*_currentL);
}
void WilhelmCBC::roundDec()
{
	*_currentR = *_currentR ^ fiestel(*_currentL);
	*_currentL = *_currentL ^ fiestel(*_currentR);
}

WilhelmCBC::LRSide WilhelmCBC::fiestel (WilhelmCBC::LRSide baseDerivation)
{
	/* Byte substitution table (stolen from Rijndael) */
	unsigned char substitutionSingleChar[256] =
	{
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
	};

	baseDerivation = baseDerivation ^ permutationKey (_baseKey, _roundNum, _blockNum);

		for (unsigned int subCounter = 0; subCounter < BLOCK_BYTES/2; subCounter++)
		{
			baseDerivation.data[subCounter] = substitutionSingleChar[baseDerivation.data[subCounter]];
		}

		// _roundNum has maximum value of 16, so 16+27 is < 64, which is the range of values for which rorLRSide behaviors reasonably.
		// In debugging I noticed a very strange convergence that happens with most vlaues of ROR_CONSTANT when _roundNum is held constant, where repeated
		//	runs of fiestel function with the same input would converge to a single value. _roundNum changes every run so it's not significant.

		baseDerivation = rorLRSide(baseDerivation, ROR_CONSTANT+_roundNum);

	return baseDerivation;
}

WilhelmCBC::LRSide WilhelmCBC::permutationKey (WilhelmCBC::Block key, unsigned long round, unsigned long blockNum)
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


WilhelmCBC::LRSide WilhelmCBC::rorLRSide (const WilhelmCBC::LRSide & input, unsigned long rotateCount)
{
	LRSide result;
	uint64_t * inputPtr = (uint64_t*)&input.data[0];
	uint64_t * resultPtr = (uint64_t*)&result.data[0];

	for (unsigned int i = 0; i < 2; i++)
		resultPtr[i] = (inputPtr[i]>>rotateCount) | (inputPtr[(i+1)%2]<<(64-rotateCount));

	return result;
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
}

WilhelmCBC::Block WilhelmCBC::Hash_SHA256_Current_Cluster ()
{
	SHA256 hash;
	hash.add(&_currentBlockSet[0],_currentBlockSet.size());
	SHA256::digest d = hash.finish();

	Block b;
	
	for (unsigned int i = 0; i < BLOCK_BYTES; i++)
	{
		b.data[i] = d.data[i];
	}

	return b;
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

// LRSide xor operator
WilhelmCBC::LRSide WilhelmCBC::LRSide::operator^ (const WilhelmCBC::LRSide & rhs) const
{
	LRSide result;
	for (unsigned int i = 0; i < (BLOCK_BYTES/2); i+=(BLOCK_BYTES/4)) // 4 bytes in a uint64_t, so divide by 4
	{
		*((uint64_t*)&result.data[i]) = *((uint64_t*)&data[i])^*((uint64_t*)&rhs.data[i]);
	}
	return result;
}

// For debugging
void	WilhelmCBC::printBlock (const WilhelmCBC::Block & b) const
{
	for (unsigned int i = 0; i < BLOCK_BYTES; i++)
	{
		std::cout << std::hex << std::setw (2) <<  std::setfill ('0') << (int)b.data[i];
	}
	std::cout << std::endl;
}

void	WilhelmCBC::printLRSide (const WilhelmCBC::LRSide& lr) const
{
	for (unsigned int i = 0; i < BLOCK_BYTES/2; i++)
	{
		std::cout << std::hex << std::setw (2) <<  std::setfill ('0') << (int)lr.data[i];
	}
	std::cout << std::endl;
}

// Debugging

void WilhelmCBC::publicDebugFunc()
{
/*
	std::cout << "Randomly generated block" << std::endl;
	Block b = IVGenerator();
	printBlock(b);

	std::cout << std::endl << "Base key, derived from 'MyPasswordIstGut?'" << std::endl;
	setKey ("MyPasswordIstGut?'");
	printBlock(_baseKey);

 */

	LRSide L;
	for (int i = 0; i < BLOCK_BYTES/2; i++)
		L.data[i] = 0;
	printLRSide (L);
	LRSide R = L;
	printLRSide (R);

	
	_currentL = &L;
	_currentR = &R;

	for (_roundNum = 0; _roundNum < FIESTEL_ROUNDS; _roundNum++)
	{
		roundEnc();
		printLRSide (*_currentL);
		printLRSide (*_currentR);
	}
}