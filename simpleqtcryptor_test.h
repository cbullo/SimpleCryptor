/*
 *  SimpleQtCryptor is an encryption library for Qt.
 *
 *  Copyright (C) 2010 Gunnar Thorburn
 *
 *  SimpleQtRC5 is free software: you can redistribute it and/or modify
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


/*
 */

#ifndef SIMPLEQTCRYPTOR_TEST_H
#define SIMPLEQTCRYPTOR_TEST_H


#include "simpleqtcryptor.h"

#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace SimpleQtCryptor {


class SelfTest {
public:
    SelfTest();
    ~SelfTest();

    bool test(std::vector<uint8_t> &testdata, std::string *outmsg);
    bool test(std::vector<uint8_t> &testdata, std::ostream *outmsg);

private:
    std::string *outString;
    std::ostream *outFile;

    void print(std::string line);

    bool test(std::vector<uint8_t> &testdata);

// RC5 tests
    bool test_key_zero_expand(std::shared_ptr<SimpleQtCryptor::Key> k);
    bool test_key_zero_s32(std::shared_ptr<SimpleQtCryptor::Key> k);
    bool test_key_zero_s64(std::shared_ptr<SimpleQtCryptor::Key> k);
    bool test_rc5_32_encrypt_8b(std::shared_ptr<SimpleQtCryptor::Key> k, const uint8_t* data, int expect);
    bool test_rc5_64_encrypt_16b(std::shared_ptr<SimpleQtCryptor::Key> k, const uint8_t* data, int expect);
    bool test_rc5_32_decrypt_8b(std::shared_ptr<SimpleQtCryptor::Key> k, const uint8_t* data, int expect);
    bool test_rc5_64_decrypt_16b(std::shared_ptr<SimpleQtCryptor::Key> k, const uint8_t* data, int expect);
    bool test_rc5_32_encrypt_decrypt_8b(std::shared_ptr<SimpleQtCryptor::Key> k, const uint8_t* data);
    bool test_rc5_64_encrypt_decrypt_16b(std::shared_ptr<SimpleQtCryptor::Key> k, const uint8_t* data);
    bool test2_CBC_encrypt_decrypt(std::shared_ptr<SimpleQtCryptor::Key> k, const std::vector<uint8_t> &data, SimpleQtCryptor::Algorithm a);
    bool test2_CFB_encrypt_decrypt(std::shared_ptr<SimpleQtCryptor::Key> k, const std::vector<uint8_t> &data, SimpleQtCryptor::Algorithm a);
    bool test2_encrypt_decrypt_pieceByPiece(std::shared_ptr<SimpleQtCryptor::Key> k, const std::vector<uint8_t> &data, SimpleQtCryptor::Algorithm a, SimpleQtCryptor::Mode m);
    bool test3_encrypt_decrypt(std::shared_ptr<SimpleQtCryptor::Key> k, const std::vector<uint8_t> &data, SimpleQtCryptor::Algorithm a, SimpleQtCryptor::Mode m);
    bool test3_decryptorwiz(std::shared_ptr<SimpleQtCryptor::Key> *kl, int kc, const std::vector<uint8_t> &data, SimpleQtCryptor::Algorithm a, SimpleQtCryptor::Mode m);

// SERPENT TESTS
    bool test_key_zero_expand_spt(std::shared_ptr<SimpleQtCryptor::Key> k);
    bool test_key_zero_spt(std::shared_ptr<SimpleQtCryptor::Key> k);
    bool test_serpent_encrypt_16b(std::shared_ptr<SimpleQtCryptor::Key> k, const uint8_t* data, int expect);
    bool test_serpent_decrypt_16b(std::shared_ptr<SimpleQtCryptor::Key> k, const uint8_t* data, int expect);
    bool test_serpent_encrypt_decrypt_16b(std::shared_ptr<SimpleQtCryptor::Key> k, const uint8_t* data);

};



} // namespace


#endif // SIMPLEQTCRYPTOR_TEST_H
