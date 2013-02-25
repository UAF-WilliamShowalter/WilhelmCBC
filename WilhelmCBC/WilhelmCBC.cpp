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
	
	_baseKey.data[0] = (uint64_t)initKey.data[0];
	_baseKey.data[1] = (uint64_t)initKey.data[8];
	_baseKey.data[2] = (uint64_t)initKey.data[16];
	_baseKey.data[3] = (uint64_t)initKey.data[24];

	// Hash key block 5 more times
	for (int i = 0; i < 5; i++)
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

WilhelmCBC::LRSide WilhelmCBC::permutationKey (WilhelmCBC::Block, unsigned int, unsigned int)
{
	
}

WilhelmCBC::Block WilhelmCBC::IVSGenerator ()
{
	
}

WilhelmCBC::Block WilhelmCBC::Padding (WilhelmCBC::Block)
{
	
}

// Hash 1 block with SHA256. Writes directly to parameter block.
void WilhelmCBC::Hash_SHA256_Block (WilhelmCBC::Block & b)
{
	SHA256 hash;
	hash.add(&b.data[0],32);
	SHA256::digest d = hash.finish();
	
	b.data[0] = (uint64_t)d.data[0];
	b.data[1] = (uint64_t)d.data[8];
	b.data[2] = (uint64_t)d.data[16];
	b.data[3] = (uint64_t)d.data[24];
}


/**** Overloaded Operators ****/

// Block asignment operator
WilhelmCBC::Block & WilhelmCBC::Block::operator= (const WilhelmCBC::Block &rhs)
{
	// Assignment
	for (unsigned int i = 0; i < 4; i++)
	{
		data[i] = rhs.data[i];
	}
	return *this;
}

// Block addition operator
WilhelmCBC::Block & WilhelmCBC::Block::operator+ (const WilhelmCBC::Block &rhs)
{
	// Addition, carries from one 64bit int to the next, ignores overflow of 256bit struct.
	// I originally forgot about carries carrying when I decided to make it a for loop. Might have been cleaner expclicitly.
	for (unsigned int i = 0; i < 4; i++)
	{
		data[i] += rhs.data[i];
		if (i < 3 && data[i] < rhs.data[i])
		{
			++data[i+1];
			if (i < 2 && data[i+1] < (data[i+1]-1))
			{
				++data[i+2];
				if (i < 1 && data[i+2] < (data[i+2]-1))
				{
					// It will be a rare blue moon when this get is executed. Adding to solid 0xF's for 192 bits...
					++data[i+3];
				}
			}
		}
	}
	
	return *this;
}