/*
 *  SimpleQtCryptor is an RC5 encryption library for Qt.
 *
 *  Copyright (C) 2010 Gunnar Thorburn
 *
 *  SimpleQtCryptor is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  ParrotShare is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "simpleqtcryptor.h"
#include "simpleqtcryptor_test.h"

#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <vector>

// Global variables
std::istream *myIn;
std::ostream *myOut;
std::ostream *myStderr;

char cmdCommand;
bool benchEncrypt;
int  benchMegabytes;
char *cmdPassword;
char *cmdSecretFile;
char *cmdSecret;
char *cmdInfile;
char *cmdOutfile;
SimpleQtCryptor::Algorithm cmdAlgorithm;
SimpleQtCryptor::Mode cmdMode;
bool cmdHeader;
bool cmdVerbose;

std::shared_ptr<SimpleQtCryptor::Key> gKey;


// Function declarations
bool encrypt();
bool decrypt();
bool test();
bool benchmark();
bool prepare();

void printVersion() {
        *myStderr << ("SimpleQtCryptor (v1.0.0)\n(C) 2000,2010,2011 Gunnar Thorburn\n    2000 Erik Hemberg\n");
}

void printUsage() {
    if ( !cmdVerbose ) printVersion();
    *myStderr << ("USAGE:\n");
    *myStderr << ("  SimpleQtCryptor -t testfile\n");
    *myStderr << ("  SimpleQtCryptor -b e|d rc532|rc564|spt Mb (benchmark Mb)\n");
    *myStderr << ("  SimpleQtCryptor -e OPTIONS\n");
    *myStderr << ("  SimpleQtCryptor -d OPTIONS\n");
    *myStderr << ("  SimpleQtCryptor -h\n");
    *myStderr << ("OPTIONS:\n");
    *myStderr << ("  -k SecretFile (preferred to -p)\n");
    *myStderr << ("  -p Secret (default = <empty>)\n");
    *myStderr << ("  -i IndataFile\n");
    *myStderr << ("  -o OutdataFile\n");
    *myStderr << ("  -rc5    : use native RC5 algorithm (default)\n");
    *myStderr << ("  -rc532  : use 32-bit RC5\n");
    *myStderr << ("  -rc564  : use 64-bit RC5\n");
    *myStderr << ("  -spt    : use Serpent algorithm\n");
    *myStderr << ("  -cbc    : CBC\n");
    *myStderr << ("  -cfb    : CFB (default)\n");
    *myStderr << ("  -n      : no header\n");
    *myStderr << ("  -v      : verbose\n");
}


int main(int argc, char *argv[]) {
    myStderr = &std::cerr;
    myIn = nullptr;
    myOut = nullptr;

    cmdCommand = 'x';
    cmdSecret = 0;
    cmdSecretFile = 0;
    cmdInfile = 0;
    cmdOutfile = 0;
    cmdAlgorithm = SimpleQtCryptor::NoAlgorithm;
    cmdMode = SimpleQtCryptor::NoMode;
    cmdHeader = true;
    cmdVerbose = false;
    bool ok = false;
    int aCtr = 2;

    if ( 1 == argc ) {
        goto failandprint;
    }
    if ( !std::strcmp("-e", argv[1]) ) {
        cmdCommand = 'e';
    } else if ( !std::strcmp("-d", argv[1]) ) {
        cmdCommand = 'd';
    } else if ( !std::strcmp("-t", argv[1]) ) {
        cmdCommand = 't';
        if ( 3 != argc ) {
            goto failandprint;
        } else {
            cmdInfile = argv[2];
            aCtr++;
        }
    } else if ( !std::strcmp("-b", argv[1]) ) {
        cmdCommand = 'b';
        if ( 5 != argc ) {
            goto failandprint;
        }
        if ( !std::strcmp("e", argv[2]) ) {
            benchEncrypt = true;
        } else if ( !std::strcmp("d", argv[2]) ) {
            benchEncrypt = false;
        } else {
            goto failandprint;
        }
        if ( !std::strcmp("rc532", argv[3]) ) {
            cmdAlgorithm = SimpleQtCryptor::RC5_32_32_20;
        } else if ( !std::strcmp("rc564", argv[3]) ) {
            cmdAlgorithm = SimpleQtCryptor::RC5_64_32_20;
        } else if ( !std::strcmp("spt", argv[3]) ) {
            cmdAlgorithm = SimpleQtCryptor::SERPENT_32;
        } else {
            goto failandprint;
        }
        benchMegabytes = atoi(argv[4]);
        if ( ! ( 0 < benchMegabytes && benchMegabytes < 1000 ) ) {
            goto failandprint;
        }
        aCtr = 5;
    } else if ( !std::strcmp("-h", argv[1]) ) {
        printUsage();
        goto success;
#ifdef WITH_SERPENT_PRINT_SBOX_H
    } else if ( !std::strcmp("-serpent-sbox-h", argv[1]) ) {
        SimpleQtCryptor::serpent_print_sbox_h();
        return 0;
#endif
    } else {
        goto failandprint;
    }

    while (aCtr < argc) {
        if ( !std::strcmp("-k", argv[aCtr]) ) {
            aCtr++;
            if (aCtr >= argc) {
                goto failandprint;
            }
            cmdSecretFile = argv[aCtr];
        } else if ( !std::strcmp("-p", argv[aCtr]) ) {
            aCtr++;
            if (aCtr >= argc) {
                goto failandprint;
            }
            cmdSecret = argv[aCtr];
        } else if ( !std::strcmp("-i", argv[aCtr]) ) {
            aCtr++;
            if (aCtr >= argc) {
                goto failandprint;
            }
            cmdInfile = argv[aCtr];
        } else if ( !std::strcmp("-o", argv[aCtr]) ) {
            aCtr++;
            if (aCtr >= argc) {
                goto failandprint;
            }
            cmdOutfile = argv[aCtr];
        } else if ( !std::strcmp("-spt", argv[aCtr]) ) {
            if ( cmdAlgorithm != SimpleQtCryptor::NoAlgorithm )
                goto failandprint;
            cmdAlgorithm = SimpleQtCryptor::SERPENT_32;
        } else if ( !std::strcmp("-rc532", argv[aCtr]) ) {
            if ( cmdAlgorithm != SimpleQtCryptor::NoAlgorithm )
                goto failandprint;
            cmdAlgorithm = SimpleQtCryptor::RC5_32_32_20;
        } else if ( !std::strcmp("-rc564", argv[aCtr]) ) {
            if ( cmdAlgorithm != SimpleQtCryptor::NoAlgorithm )
                goto failandprint;
            cmdAlgorithm = SimpleQtCryptor::RC5_64_32_20;
        } else if ( !std::strcmp("-rc5", argv[aCtr]) ) {
            if ( cmdAlgorithm != SimpleQtCryptor::NoAlgorithm )
                goto failandprint;
            cmdAlgorithm = SimpleQtCryptor::Info::fastRC5();
        } else if ( !std::strcmp("-cbc", argv[aCtr]) ) {
            cmdMode = SimpleQtCryptor::ModeCBC;
        } else if ( !std::strcmp("-cfb", argv[aCtr]) ) {
            cmdMode = SimpleQtCryptor::ModeCFB;
        } else if ( !std::strcmp("-n", argv[aCtr]) ) {
            cmdHeader = false;
        } else if ( !std::strcmp("-v", argv[aCtr]) ) {
            cmdVerbose = true;
            printVersion();
        } else {
            *myStderr << ("Unrecognised argument: ");
            *myStderr << (argv[aCtr]);
            *myStderr << ("\n");
            goto failandprint;
        }
        aCtr++;
    }   

    switch (cmdCommand) {
    case 't':
        ok = test();
        break;
    case 'b':
        ok = benchmark();
        break;
    case 'e':
        ok = prepare();
        if (ok) ok = encrypt();
        break;
    case 'd':
        ok = prepare();
        if (ok) ok = decrypt();
        break;
    default:
        goto failandprint;
    }

    if (!ok) goto failure;

success:
    // if (myIn) myIn->close;
    // if (myOut) myOut->close();
    // myStderr->close();
    return 0;
failandprint:
    printUsage();
failure:
    // if (myIn) myIn->close();
    // if (myOut) myOut->close();
    // myStderr->close();
    return 1;
}

bool prepare() {
    if ( 0 == cmdSecret && 0 == cmdSecretFile ) {
        if (cmdVerbose) *myStderr << ("Using empty Secret\n");
        gKey = std::make_shared<SimpleQtCryptor::Key>(std::string(""));
    } else if ( 0 != cmdSecret && 0 != cmdSecretFile ) {
        *myStderr << ("Error: use either -k or -p\n");
    } else if ( 0 != cmdSecret ) {
        std::cout << cmdSecret << std::endl;
        gKey = std::make_shared<SimpleQtCryptor::Key>(std::string(cmdSecret));
    } else {
        std::ifstream kfile(cmdSecretFile, std::ios_base::binary);
        if (!kfile.is_open()) {
            *myStderr << ("failed to open secret file ");
            *myStderr << (cmdSecretFile);
            *myStderr << ("\n");
            return false;
        }
        
        std::vector<uint8_t> k;
        if (!kfile.eof()) {
            kfile.seekg(0, std::ios_base::end);
            std::streampos fileSize = kfile.tellg();
            k.resize(fileSize);

            kfile.seekg(0, std::ios_base::beg);
            kfile.read(reinterpret_cast<char*>(&k[0]), fileSize);
        }
        gKey = std::make_shared<SimpleQtCryptor::Key>(k);
        if (cmdVerbose) {
            *myStderr << ("using contents of  ");
            *myStderr << (cmdSecretFile);
            *myStderr << (" as encryption key\n");
        }
    }

    if ( 0 == cmdInfile ) {
        myIn = &std::cin;
    } else {
        myIn = new std::ifstream(cmdInfile, std::ios_base::binary);
        if ( ! *myIn ) {
            delete myIn;
            myIn = 0;
            *myStderr << ("Failed to open Input File ");
            *myStderr << (cmdInfile);
            *myStderr << ("\n");
            return false;
        }
    }

    if ( 0 == cmdOutfile ) {
        myOut = &std::cout;
    } else {
        myOut = new std::ofstream(cmdOutfile, std::ios_base::binary);
        if ( ! *myOut ) {
            delete myOut;
            myOut = 0;
            *myStderr << ("Failed to open Output File ");
            *myStderr << (cmdOutfile);
            *myStderr << ("\n");
            return false;
        }
    }

    return true;
}

bool test() {
    std::string testfilename(cmdInfile);
    std::ifstream testfile(testfilename, std::ios_base::binary);
    if ( ! testfile ) {
         *myStderr << ("Can not open testfile ");
         *myStderr << (testfilename);
         *myStderr << ("\n");
        return false;
    }

    std::vector<uint8_t> testdata;
    if (!testfile.eof()) {
        testfile.seekg(0, std::ios_base::end);
        std::streampos fileSize = testfile.tellg();
        testdata.resize(fileSize);

        testfile.seekg(0, std::ios_base::beg);
        testfile.read(reinterpret_cast<char*>(&testdata[0]), fileSize);
    }

    SimpleQtCryptor::SelfTest st;
    return st.test(testdata, myStderr);
}

bool benchmark() {
    *myStderr << ("Benchmarking...");
    int i;
    SimpleQtCryptor::Key *k = new SimpleQtCryptor::Key();
    if ( cmdAlgorithm == SimpleQtCryptor::RC5_32_32_20 ) {
        uint32_t X1 = 0;
        uint32_t X2 = 0;
        k->expandKeyRc532();
        i = benchMegabytes * 128000;
        if ( benchEncrypt ) while ( i-- ) {
            SimpleQtCryptor::rc5_32_encrypt_2w(X1, X2, k->s32);
        } else while ( i-- ) {
            SimpleQtCryptor::rc5_32_decrypt_2w(X1, X2, k->s32);
        }
    } else if ( cmdAlgorithm == SimpleQtCryptor::RC5_64_32_20 ) {
        uint64_t X1 = 0;
        uint64_t X2 = 0;
        k->expandKeyRc564();
        i = benchMegabytes * 64000;
        if ( benchEncrypt ) while ( i-- ) {
            SimpleQtCryptor::rc5_64_encrypt_2w(X1, X2, k->s64);
        } else while ( i-- ) {
            SimpleQtCryptor::rc5_64_decrypt_2w(X1, X2, k->s64);
        }
    } else if ( cmdAlgorithm == SimpleQtCryptor::SERPENT_32 ) {
        uint32_t X1 = 0;
        uint32_t X2 = 0;
        uint32_t X3 = 0;
        uint32_t X4 = 0;
        k->expandKeySerpent();
        i = benchMegabytes * 64000;
        if ( benchEncrypt ) while ( i-- ) {
            SimpleQtCryptor::serpent_encrypt_4w(X1, X2, X3, X4, k->serpent);
        } else while ( i-- ) {
            SimpleQtCryptor::serpent_decrypt_4w(X1, X2, X3, X4, k->serpent);
        }
    }
    *myStderr << ("...done");
    delete k;
    return true;
}

bool encrypt() {
    SimpleQtCryptor::Encryptor *enc = 0;
    SimpleQtCryptor::LayerMode *mox = 0;

    if ( cmdAlgorithm == SimpleQtCryptor::NoAlgorithm ) {
        cmdAlgorithm = SimpleQtCryptor::Info::fastRC5();
        if (cmdVerbose) {
            *myStderr << ("Defaulting to fastest algorithm for this machine\n");
        }
    }
    if ( cmdMode == SimpleQtCryptor::NoMode ) {
        cmdMode = SimpleQtCryptor::ModeCFB;
        if (cmdVerbose) {
            *myStderr << ("Defaulting to CFB mode\n");
        }
    }

    if ( cmdHeader ) {
        if (cmdVerbose) {
            *myStderr << ("A little (encrypted) header is written to the file making\n");
            *myStderr << ("  it possible to decrypt it without parameters\n");
        }
        enc = new SimpleQtCryptor::Encryptor(gKey, cmdAlgorithm, cmdMode, SimpleQtCryptor::NoChecksum);
    } else {
        if (cmdVerbose) {
            *myStderr << ("No header is written to this file. Remember your parameters!\n");
        }
        if ( SimpleQtCryptor::ModeCBC == cmdMode ) {
            mox = new SimpleQtCryptor::CBC(gKey, cmdAlgorithm);
        } else {
            mox = new SimpleQtCryptor::CFB(gKey, cmdAlgorithm);
        }
    }

    myStderr->flush();

    std::vector<uint8_t> indata(512000);
    std::vector<uint8_t> cipher;
    SimpleQtCryptor::Error er = SimpleQtCryptor::NoError;
    do {
        //indata = myIn->read(512000);
        indata.resize(512000);
        myIn->read(reinterpret_cast<char*>(&indata[0]), 512000);
        indata.resize(myIn->gcount());
        if ( cmdHeader ) {
            er = enc->encrypt(indata, cipher, indata.empty());
        } else {
            cipher = mox->encrypt(indata, indata.empty());
        }
        if (SimpleQtCryptor::NoError != er) {
            *myStderr << ("Encryption error (very unexpected)\n");
            return false;
        }
        myOut->write(reinterpret_cast<char*>(&cipher[0]), cipher.size());
        myOut->flush();
        cipher.clear();
    } while ( !indata.empty() );
    delete mox;
    delete enc;
    if (myIn->fail()) {
        *myStderr << ("ERROR reading indata\n");
        return false;
    }
    return true;
}

bool decrypt() {
    std::shared_ptr<SimpleQtCryptor::Decryptor> dec;
    SimpleQtCryptor::DecryptorWizard *dew = 0;
    SimpleQtCryptor::LayerMode *mox = 0;

    if ( cmdAlgorithm == SimpleQtCryptor::NoAlgorithm ) {
        if (cmdHeader) {
            cmdAlgorithm = SimpleQtCryptor::DetectAlgorithm;
            if (cmdVerbose) {
                *myStderr << ("Defaulting to automatically detect algorithm\n");
            }
        } else {
            cmdAlgorithm = SimpleQtCryptor::Info::fastRC5();
            if (cmdVerbose) {
                *myStderr << ("Defaulting to fastest algorithm for this machine\n");
            }
        }
    }
    if ( cmdMode == SimpleQtCryptor::NoMode ) {
        if (!cmdHeader) {
            cmdMode = SimpleQtCryptor::ModeCFB;
            *myStderr << ("Defaulting to CFB mode\n");
        } else {
            cmdMode = SimpleQtCryptor::DetectMode;
            if (cmdVerbose) {
                *myStderr  << ("Defaulting to automatically detect mode\n");
            }
        }
    }

    if ( cmdHeader ) {
        dew = new SimpleQtCryptor::DecryptorWizard(gKey, cmdAlgorithm, cmdMode);
    } else {
        if ( SimpleQtCryptor::ModeCBC == cmdMode ) {
            mox = new SimpleQtCryptor::CBC(gKey, cmdAlgorithm);
        } else {
            mox = new SimpleQtCryptor::CFB(gKey, cmdAlgorithm);
        }
    }

    myStderr->flush();

    std::vector<uint8_t> indata(512000);
    std::vector<uint8_t> plain;
    SimpleQtCryptor::Error er = SimpleQtCryptor::NoError;
    do {
        //indata = myIn->read(512000);
        indata.resize(512000);
        myIn->read(reinterpret_cast<char*>(&indata[0]), 512000);
        indata.resize(myIn->gcount());
        if ( cmdHeader ) {
            if (!dec) {
                er = dew->decrypt(indata, plain, dec, indata.empty());
                std::cout << "Using wizard" << std::endl;
            } else {
                er = dec->decrypt(indata, plain, indata.empty());
            }
        } else {
            plain = mox->decrypt(indata, myIn->eof());
        }
        if (SimpleQtCryptor::NoError != er) {
            *myStderr << ("Decryption error: ");
            *myStderr << (SimpleQtCryptor::Info::errorText(er));
            *myStderr << ("\n");
            return false;
        }
        myOut->write(reinterpret_cast<char*>(&plain[0]), plain.size());
        myOut->flush();
        plain.clear();
    } while ( ! indata.empty() );
    if (myIn->fail()) {
        *myStderr << ("ERROR reading indata\n");
        return false;
    }
    return true;
}





