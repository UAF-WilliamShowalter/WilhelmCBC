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
 
 
	Header for WilhelmCBC class
 
	Basic Encryption Flow Structure:
	********************************
	setInput(file);
	setOutput(file);
	setKey (password);
 
	encrypt();
		->	encCBC();
			-> blockEnc();
				-> roundEnc();
 
	decrypt();
		 ->	decCBC();
			 -> blockDec();
				 -> roundDec();
	********************************
	
	setInput or setOutput may throw. Client code should check for errors. Exceptions documented in definitions.

*/


#ifndef __WilhelmCBC__WilhelmCBC__
#define __WilhelmCBC__WilhelmCBC__

#include <iostream>		// debugging to console

#include <string>		// std::string
#include <stdint.h>		// uint64_t
#include <fstream>		// file IO
#include <vector>		// std::vector

#include "SHA256.h"		// Public Domain SHA256 hash function

class WilhelmCBC {
public:
// Public Methods
	void setInput (std::string filename);
	void setOutput (std::string filename);
	void setKey (std::string password);
	bool encrypt ();
	bool decrypt ();

private:
// Types
	// Block, used for referencing 1 Block of data.
	struct Block {
		uint64_t data[4];
	};

	// LRSide, used for referencing 1 side in a fiestel process.
	struct LRSide {
		uint64_t data[2];
	};

	Block& operator= (const Block &rhs);

private:
// Private Methods
	void encCBC();
	void decCBC();
	void blockEnc();
	void blockDec();
	void roundEnc();
	void roundDec();

	LRSide	fiestel (LRSide);
	LRSide	permutationKey (Block, unsigned int, unsigned int);
	Block	IVSGenerator ();
	Block	Padding (Block);
	void	Hash_SHA256_Block (Block &);

// Private Data Members
	std::ifstream	_ifile;
	std::ofstream	_ofile;
	unsigned long	_indexToStream;
	unsigned long	_blockNum;
	unsigned long	_roundNum;
	std::size_t		_inputSize;
	Block			_baseKey;
	Block *			_currentBlock;
	std::vector<char> _currentBlockSet;
	
};

#endif /* defined(__WilhelmCBC__WilhelmCBC__) */
