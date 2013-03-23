/*
 Written by William Showalter. williamshowalter@gmail.com.
 Date Last Modified: 2013 March 23
 Created: 2013 February 23

 Released under Creative Commons - creativecommons.org/licenses/by-nc-sa/3.0/
 Attribution-NonCommercial-ShareAlike 3.0 Unported (CC BY-NC-SA 3.0)

 Includes timing code written by Dr. Orion Sky Lawlor, lawlor@alaska.edu, in "NetRunlib.h".
 Code written in NetRunlib.h remains the copyright of Dr. Orion Sky Lawlor.
 
 **NOTE**
 I am not a crytologist/cryptanalyst and this software has not been heavily analyzed for security,
 so you should use it to protect actual sensitive data.

 Software is provided as is with no guarantees.


 Driver for WilhelmCBC class
 */

#include <iostream>
#include <stdexcept>
#include "WilhelmCBC.h"
#include "NetRunlib.h"

// Function Prototypes
void menu();
void timePrint (double time1, double time2, int dataSize);

enum BYTES {BYTES = 0, KILOBYTES = 1, MEGABYTES = 2, GIGABYTES = 3};


int main(int argc, const char * argv[])
{
	// Call the menu wrapper
	menu();
}

void menu ()
{
    /*
     This function runs a loop to prompt the user for input.
     
     Menu loop prompts are:
     1. Encryption
     2. Decryption
     3. Exit
     
     Options 1 & 2 will ask for input, key, and output file paths.
     
     Will reprompt if file paths are invalid.
     */
    
    
    
    // Paths to our input files
    
    std::string inputfilepath;
    std::string keyPhrase;
    std::string outputfilepath;
    
    // Menu Code - pretty much self documenting switch statements.
    int menuselection;
    while (true)
    {
        std::cout   << "Please make a selection:\n"
        << "1. Encryption\n" << "2. Decryption\n" << "3. Exit\n" << "Selection #: ";
        std::cin    >> menuselection;
        
        std::cin.ignore(); // Getline will read the last line return and not read in any data without an ignore.
        
        switch (menuselection)
        {
            case (1): // Encryption
            {
                std::cout   << std::endl << "Please input the path to the file to be encrypted:\n";
                std::getline (std::cin, inputfilepath);
                
                std::cout   << std::endl << "Please input a passphrase to use:\n";
                std::getline (std::cin, keyPhrase);
                
                std::cout   << std::endl << "Please input a path for the output file:\n";
                std::getline (std::cin, outputfilepath);
                
                std::cout   << std::endl;
                try {
					WilhelmCBC encryptObj;
                    double t1 = time_in_seconds();
                    encryptObj.setInput (inputfilepath);
					encryptObj.setKey (keyPhrase);
					encryptObj.setOutput (outputfilepath);
					encryptObj.encrypt();
                    double t2 = time_in_seconds();
                    
                    timePrint (t1, t2, encryptObj.getSize());
                }
                
                catch (std::runtime_error e) {
                    std::cout << "\n\n******\n" << e.what() << "\n******\n\n";
                }
                
                catch (std::bad_alloc e) {
                    std::cout << "\n\n******\n" << "Allocation Error - Sufficient memory might not be available.\n" << e.what() << "\n******\n\n";
                }
                
                catch (...) {
                    std::cout << "\n\n******\n" << "Unspecified Exception Caught: Restarting Menu" << "\n******\n\n";
                }
                break;
                
                break;
            }
                
            case (2):
            {
                std::cout   << std::endl << "Please input the path to the file to be decrypted:\n";
                std::getline (std::cin, inputfilepath);
                
                std::cout   << std::endl << "Please input a passphrase to use:\n";
                std::getline (std::cin, keyPhrase);
                
                std::cout   << std::endl << "Please input a path for the output file:\n";
                std::getline (std::cin, outputfilepath);
                
                std::cout   << std::endl;
                
                try
                {
                    double t1 = time_in_seconds();
					WilhelmCBC decryptObj;

					decryptObj.setInput(inputfilepath);
					decryptObj.setKey(keyPhrase);
					decryptObj.setOutput(outputfilepath);

                    bool success = decryptObj.decrypt();

                    double t2 = time_in_seconds();
                    
                    timePrint (t1, t2, decryptObj.getSize());
                    
                    if (success)
                        std::cout << std::endl << "Successfully decrypted - HMAC matched" << std::endl << std::endl;
                    else
                        std::cout << std::endl << "Unsuccessful decryption - HMAC failed" << std::endl << std::endl;
                }
                
                catch (std::runtime_error e) {
                    std::cout << "\n\n******\n" << e.what() << "\n******\n\n";
                }
                
                catch (std::bad_alloc e) {
                    std::cout << "\n\n******\n" << "Allocation Error - Sufficient memory might not be available.\n" << e.what() << "\n******\n\n";
                }
                
                catch (...) {
                    std::cout << "\n\n******\n" << "Unspecified Exception Caught: Restarting Menu" << "\n******\n\n";
                }
                break;
            }
                
            case (3):
            {
                exit(0);
            }
            default:
            {
                std::cout << "Please choose from the choices below:\n";
            }
        }
    }
}


void timePrint (double time1, double time2, int dataSize)
{
    /*
     Calculates and prints to console the data speed of a given operation.
     
     time1 & time2 are the times before and after the operation.
     dataSize is the size (in bytes) of the data operated on.
     
     */
    
    int byteCounter = 0;
    
    double bytesPerSecond = (dataSize)/(time2-time1);
    
    if (bytesPerSecond > 1024)
    {
        byteCounter = KILOBYTES;
        bytesPerSecond = bytesPerSecond / 1024;
    }
    
    if (bytesPerSecond > 1024)
    {
        byteCounter = MEGABYTES;
        bytesPerSecond = bytesPerSecond / 1024;
    }
    
    if (bytesPerSecond > 1024)
    {
        byteCounter = GIGABYTES;
        bytesPerSecond = bytesPerSecond / 1024;
    }
    
    std::string byteUnits;
    switch (byteCounter)
    {
        case (BYTES):
            byteUnits = "B/s";
            break;
        case (KILOBYTES):
            byteUnits = "KB/s";
            break;
        case (MEGABYTES):
            byteUnits = "MB/s";
            break;
        default: 
            byteUnits = "GB/s";
    }
    
    std::cout << "\n Processed at an average rate of: " << bytesPerSecond << " " << byteUnits << std::endl << std::endl;
    
}