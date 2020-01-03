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

#include "simpleqtcryptor_test.h"
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/format.hpp>
#include <sstream>

namespace SimpleQtCryptor {

static const uint16_t crc_tbl[16] = {
    0x0000, 0x1081, 0x2102, 0x3183,
    0x4204, 0x5285, 0x6306, 0x7387,
    0x8408, 0x9489, 0xa50a, 0xb58b,
    0xc60c, 0xd68d, 0xe70e, 0xf78f
};

uint16_t qChecksum(const uint8_t *data, uint len)
{
    uint16_t crc = 0xffff;
    uint8_t c;
    const uint8_t *p = reinterpret_cast<const uint8_t *>(data);
    while (len--) {
        c = *p++;
        crc = ((crc >> 4) & 0x0fff) ^ crc_tbl[((crc ^ c) & 15)];
        c >>= 4;
        crc = ((crc >> 4) & 0x0fff) ^ crc_tbl[((crc ^ c) & 15)];
    }
    return ~crc & 0xffff;
}

SelfTest::SelfTest() {}

SelfTest::~SelfTest() {}

std::string getRandomString() {
  // typedef boost::archive::iterators::base64_from_binary<
  //     boost::archive::iterators::transform_width<const char *, 6, 8> >
  //     base64_text;

  // std::vector<char> tmp(2 + std::rand() % 18, 0);
  // std::stringstream os;
  // std::copy(base64_text(tmp.begin()), base64_text(tmp.end()),
  //           boost::archive::iterators::ostream_iterator<char>(os));
  // return os.str();

  std::string tmp(2 + std::rand() % 18, 0);
  return tmp;
}

void SelfTest::print(std::string line) {
  if (0 == outString) {
    *outFile << line;
    outFile->flush();
  } else {
    *outString += line;
  }
}

// Function implementations

bool SelfTest::test_key_zero_expand(std::shared_ptr<SimpleQtCryptor::Key> k) {
  int expect = 58000;
  k->expandKeyRc532();
  int value = qChecksum(k->keyRc5.data(), k->keyRc5.size());
  if (expect != value) {
    print((boost::format("\n  FAILED: checksum of RC5 key was %1%, expected %2%\n")
               % value
               % expect).str());
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test_key_zero_expand_spt(
    std::shared_ptr<SimpleQtCryptor::Key> k) {
  int expect = 52592;
  k->expandKeySerpent();
  int value = qChecksum(k->keySerpent.data(), k->keySerpent.size());
  if (expect != value) {
    print((boost::format("\n  FAILED: checksum of RC5 key was %1%, expected %2%\n")
              % value
              % expect).str());
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test_key_zero_s32(std::shared_ptr<SimpleQtCryptor::Key> k) {
  uint32_t expect = 3283408660UL;
  k->expandKeyRc532();
  uint32_t value = 0;
  for (int i = 0; i < 66; i++) {
    value ^= k->s32[i];
  }
  if (expect != value) {
    print((boost::format("\n  FAILED: checksum of key was %1%, expected %2%\n")
              % value
              % expect).str());
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test_key_zero_s64(std::shared_ptr<SimpleQtCryptor::Key> k) {
  uint64_t expect = 13974939462919509502ULL;
  k->expandKeyRc564();
  uint64_t value = 0;
  for (int i = 0; i < 66; i++) {
    value ^= k->s64[i];
  }
  if (expect != value) {
    print((boost::format("\n  FAILED: checksum of key was %1%, expected %2%\n")
              % value
              % expect).str());
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test_key_zero_spt(std::shared_ptr<SimpleQtCryptor::Key> k) {
  uint32_t expect = 2347418874UL;
  k->expandKeySerpent();
  uint32_t value = 0;
  for (int i = 0; i < 132; i++) {
    value ^= k->serpent[i];
  }
  if (expect != value) {
    print((boost::format("\n  FAILED: checksum of key was %1%, expected %2%\n")
              % value
              % expect).str());
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test_rc5_32_encrypt_8b(std::shared_ptr<SimpleQtCryptor::Key> k,
                                      const uint8_t *data, int expect) {
  uint8_t cph[8];
  SimpleQtCryptor::rc5_32_encrypt_8b(data, cph, k->s32);
  int value = qChecksum((uint8_t *)cph, 8);
  if (expect != value) {
    print((boost::format("\n  FAILED: checksum of ciphertext was %1%, expected %2%\n")
              % value
              % expect).str());
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test_rc5_64_encrypt_16b(std::shared_ptr<SimpleQtCryptor::Key> k,
                                       const uint8_t *data, int expect) {
  uint8_t cph[16];
  SimpleQtCryptor::rc5_64_encrypt_16b(data, cph, k->s64);
  int value = qChecksum((uint8_t *)cph, 16);
  if (expect != value) {
    print((boost::format("\n  FAILED: checksum of ciphertext was %1%, expected %2%\n")
              % value
              % expect).str());
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test_rc5_32_decrypt_8b(std::shared_ptr<SimpleQtCryptor::Key> k,
                                      const uint8_t *data, int expect) {
  uint8_t pln[8];
  SimpleQtCryptor::rc5_32_decrypt_8b(data, pln, k->s32);
  int value = qChecksum((uint8_t *)pln, 8);
  if (expect != value) {
    print((boost::format("\n  FAILED: checksum of plaintext was %1%, expected %2%\n")
              % value
              % expect).str());
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test_rc5_64_decrypt_16b(std::shared_ptr<SimpleQtCryptor::Key> k,
                                       const uint8_t *data, int expect) {
  uint8_t pln[16];
  SimpleQtCryptor::rc5_64_decrypt_16b(data, pln, k->s64);
  int value = qChecksum((uint8_t *)pln, 16);
  if (expect != value) {
    print((boost::format("\n  FAILED: checksum of plaintext was %1%, expected %2%\n")
              % value
              % expect).str());
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test_serpent_encrypt_16b(std::shared_ptr<SimpleQtCryptor::Key> k,
                                        const uint8_t *data, int expect) {
  uint8_t cph[16];
  SimpleQtCryptor::serpent_encrypt_16b(data, cph, k->serpent);
  int value = qChecksum((uint8_t *)cph, 16);
  if (expect != value) {
    print((boost::format("\n  FAILED: checksum of ciphertext was %1%, expected %2%\n")
              % value
              % expect).str());
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test_serpent_decrypt_16b(std::shared_ptr<SimpleQtCryptor::Key> k,
                                        const uint8_t *data, int expect) {
  uint8_t pln[16];
  SimpleQtCryptor::serpent_decrypt_16b(data, pln, k->serpent);
  int value = qChecksum((uint8_t *)pln, 16);
  if (expect != value) {
    print((boost::format("\n  FAILED: checksum of plaintext was %1%, expected %2%\n")
              % value
              % expect).str());
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test_rc5_32_encrypt_decrypt_8b(
    std::shared_ptr<SimpleQtCryptor::Key> k, const uint8_t *data) {
  uint8_t cip[8];
  uint8_t pln[8];
  SimpleQtCryptor::rc5_32_encrypt_8b(data, cip, k->s32);
  SimpleQtCryptor::rc5_32_decrypt_8b(cip, pln, k->s32);
  if (qChecksum((uint8_t *)data, 8) != qChecksum((uint8_t *)pln, 8)) {
    print((boost::format("\n  FAILED: decryption did not recover plaintext\n")).str());
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test_rc5_64_encrypt_decrypt_16b(
    std::shared_ptr<SimpleQtCryptor::Key> k, const uint8_t *data) {
  uint8_t cip[16];
  uint8_t pln[16];
  SimpleQtCryptor::rc5_64_encrypt_16b(data, cip, k->s64);
  SimpleQtCryptor::rc5_64_decrypt_16b(cip, pln, k->s64);
  if (qChecksum((uint8_t *)data, 16) != qChecksum((uint8_t *)pln, 16)) {
    print((boost::format("\n  FAILED: decryption did not recover plaintext\n")).str());
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test_serpent_encrypt_decrypt_16b(
    std::shared_ptr<SimpleQtCryptor::Key> k, const uint8_t *data) {
  uint8_t cip[16];
  uint8_t pln[16];
  SimpleQtCryptor::serpent_encrypt_16b(data, cip, k->serpent);
  SimpleQtCryptor::serpent_decrypt_16b(cip, pln, k->serpent);
  if (qChecksum((uint8_t *)data, 16) != qChecksum((uint8_t *)pln, 16)) {
    print((boost::format("\n  FAILED: decryption did not recover plaintext\n")).str());
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test2_CBC_encrypt_decrypt(std::shared_ptr<SimpleQtCryptor::Key> k,
                                         const std::vector<uint8_t> &data,
                                         SimpleQtCryptor::Algorithm a) {
  SimpleQtCryptor::CBC cbc(k, a);
  std::vector<uint8_t> cipher = cbc.encrypt(data, true);
  std::vector<uint8_t> plain = cbc.decrypt(cipher, true);
  if (data.size() != plain.size()) {
    print((boost::format("\n  FAILED: recovered plaintext not same size as original "
                  "(%1, not %2)\n")
              % (plain.size())
              % (data.size())).str());
    return false;
  }
  if (qChecksum(data.data(), data.size()) !=
      qChecksum(plain.data(), plain.size())) {
    print(
        std::string("\n  FAILED: recovered plaintext not identical to original\n"));
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test2_CFB_encrypt_decrypt(std::shared_ptr<SimpleQtCryptor::Key> k,
                                         const std::vector<uint8_t> &data,
                                         SimpleQtCryptor::Algorithm a) {
  SimpleQtCryptor::CFB cfb(k, a);
  std::vector<uint8_t> cipher = cfb.encrypt(data);
  cfb.reset();
  std::vector<uint8_t> plain = cfb.decrypt(cipher);
  cfb.reset();
  if (data.size() != plain.size()) {
    print((boost::format("\n  FAILED: recovered plaintext not same size as original "
                  "(%1, not %2)\n")
              % (plain.size())
              % (data.size())).str());
    return false;
  }
  if (qChecksum(data.data(), data.size()) !=
      qChecksum(plain.data(), plain.size())) {
    print(
        std::string("\n  FAILED: recovered plaintext not identical to original\n"));
    return false;
  } else {
    print((boost::format(" passed\n")).str());
  }
  return true;
}

bool SelfTest::test2_encrypt_decrypt_pieceByPiece(
    std::shared_ptr<SimpleQtCryptor::Key> k, const std::vector<uint8_t> &data,
    SimpleQtCryptor::Algorithm a, SimpleQtCryptor::Mode m) {
  SimpleQtCryptor::LayerMode *modex;
  int64_t tmpl = 0;
  int64_t tmpx = 0;
  int ps = -1;
  int cs = -1;
  int half = -1;
  std::vector<uint8_t> cipher;
  std::vector<uint8_t> cipherNN;
  std::vector<uint8_t> cipher0X0;
  std::vector<uint8_t> cipherR;
  std::vector<uint8_t> cipherC;
  std::vector<uint8_t> plain;

  std::vector<uint8_t> tmp1;
  std::vector<uint8_t> tmp2;

  std::string descList[4] = {std::string("ALL-IN-ONE"), std::string("SPLIT-IN-TWO"),
                         std::string("EMPTY-HEAD-AND-TAIL"),
                         std::string("SPLIT-RANDOMLY")};

  int decOrderList[8][4] = {{1, 2, 3, 0}, {1, 3, 0, 2}, {2, 0, 3, 1},
                            {2, 3, 0, 1}, {2, 3, 1, 0}, {3, 0, 1, 2},
                            {3, 2, 0, 1}, {3, 2, 1, 0}};
  int *decOrder = decOrderList[std::rand() % 8];

  // int decOrder[4] = { 0,0,0,0 };
  if (m == SimpleQtCryptor::ModeCBC) {
    modex = new SimpleQtCryptor::CBC(k, a);
  } else if (m == SimpleQtCryptor::ModeCFB) {
    modex = new SimpleQtCryptor::CFB(k, a);
  } else {
    return false;
  }

  ps = qChecksum((uint8_t *)data.data(), data.size());

  // 1. Encrypt everything at once
  cipher = modex->encrypt(data, true);
  cs = qChecksum((uint8_t *)cipher.data(), cipher.size());

  // 2. Encrypt in two pices
  half = data.size() / 2;
  cipherNN = modex->encrypt(std::vector<uint8_t>(data.begin(), data.begin() + half), false);
  auto secondHalf = modex->encrypt(std::vector<uint8_t>(data.begin() + half, data.end()), true);
  cipherNN.insert(cipherNN.end(), secondHalf.begin(), secondHalf.end());
  if (cipher.size() != cipherNN.size()) {
    print((boost::format(
              "\n  FAILED: encrypting (%1%) gave wrong cipher size (%2% not %3%\n")
              % (descList[1])
              % (cipherNN.size())
              % (cipher.size())).str());
    goto failure;
  }

  // 3. Encrypt first block of 0 size, then everything, and then finally another
  // block of 0
  cipher0X0 = modex->encrypt(std::vector<uint8_t>(), false);
  tmp1 = modex->encrypt(data, false);
  cipher0X0.insert(cipher0X0.end(), tmp1.begin(), tmp1.end());
  tmp2 = modex->encrypt(std::vector<uint8_t>(), true);
  cipher0X0.insert(cipher0X0.end(), tmp2.begin(), tmp2.end());
  if (cipher.size() != cipher0X0.size()) {
    print((boost::format(
              "\n  FAILED: encrypting (%1%) gave wrong cipher size (%2% not %3%\n")
              % (descList[2])
              % (cipher0X0.size())
              % (cipher.size())).str());
    goto failure;
  }

  // 4. Encrypt in random block of size 0-47 bytes
  cipherR = std::vector<uint8_t>();
  do {
    tmpx = std::min((int64_t)(std::rand() % 48), (int64_t)data.size() - tmpl);
    tmp1 = modex->encrypt(std::vector<uint8_t>(data.begin() + tmpl, data.begin() + tmpl + tmpx), tmpx + tmpl == data.size());
    cipherR.insert(cipherR.end(), tmp1.begin(), tmp1.end());
    tmpl += tmpx;
  } while (tmpl < data.size());
  if (cipher.size() != cipherR.size()) {
    print(
        (boost::format(
            "\n  FAILED: encrypting (%1) gave wrong cipher size (%2% not %3%)\n")
            % (descList[3])
            % (cipherR.size())
            % (cipher.size())).str());
    goto failure;
  }

  for (int i = 0; i < 4; i++) {
    switch (i) {
      case 0:
        cipherC = cipher;
        break;
      case 1:
        cipherC = cipherNN;
        break;
      case 2:
        cipherC = cipher0X0;
        break;
      case 3:
      default:
        cipherC = cipherR;
    }

    switch (decOrder[i]) {
      case 0:
        // 1. Encrypt everything at once
        plain = modex->decrypt(cipherC, true);
        break;
      case 1:
        // 2. Decrypt half and half
        half = cipherC.size() / 2;
        plain = modex->decrypt(std::vector<uint8_t>(cipherC.begin(), cipherC.begin() + half), false);
        tmp1 = modex->decrypt(std::vector<uint8_t>(cipherC.end() - (cipherC.size() - half), cipherC.end()), true);
        plain.insert(plain.end(), tmp1.begin(), tmp1.end());
        break;
      case 2:
        // 3. Encrypt first block of 0 size, then everything, and then finally
        // another block of 0
        plain = modex->decrypt(std::vector<uint8_t>(), false);
        tmp1 = modex->decrypt(cipherC, false);
        plain.insert(plain.end(), tmp1.begin(), tmp1.end());
        tmp2 = modex->decrypt(std::vector<uint8_t>(), true);
        plain.insert(plain.end(), tmp2.begin(), tmp2.end());
        break;
      case 3:
      default:
        tmpl = tmpx = 0;
        while (tmpl < cipherC.size()) {
          tmpx = std::min((int64_t)(std::rand() % 48), (int64_t)cipherC.size() - tmpl);
          tmp1 = modex->decrypt(std::vector<uint8_t>(cipherC.begin() + tmpl, cipherC.begin() + tmpl + tmpx), tmpx + tmpl == cipherC.size());
          plain.insert(plain.end(), tmp1.begin(), tmp1.end());
          tmpl += tmpx;
        }
        break;
    }
    if (plain.size() != data.size()) {
      print((boost::format("\n  FAILED: encrypting (%1%) and decrypting (%2%)\n")
                % (descList[i])
                % (descList[decOrder[i]])).str());
      print((boost::format("          gave wrong plain size (%1 not %2)\n")
                % (plain.size())
                % (data.size())).str());
      goto failure;
    }
    if (ps != qChecksum((uint8_t *)plain.data(), plain.size())) {
      print((boost::format("\n  FAILED: encrypting (%1%) and decrypting (%2%)\n")
                % (descList[i])
                % (descList[decOrder[i]])).str());
      print((boost::format("          gave wrong plain text data\n")).str());
      goto failure;
    }
    plain.clear();
  }
  cs = cs;  // to avoid warnings
  delete modex;
  print((boost::format(" passed\n")).str());
  return true;
failure:
  delete modex;
  return false;
}

bool SelfTest::test3_encrypt_decrypt(std::shared_ptr<SimpleQtCryptor::Key> k,
                                     const std::vector<uint8_t> &data,
                                     SimpleQtCryptor::Algorithm a,
                                     SimpleQtCryptor::Mode m) {
  SimpleQtCryptor::Encryptor ex(k, a, m, SimpleQtCryptor::NoChecksum);
  SimpleQtCryptor::Decryptor dx(k, a, m);
  std::vector<uint8_t> ct;
  std::vector<uint8_t> pt;
  SimpleQtCryptor::Error er;
  er = ex.encrypt(data, ct, true);
  if (SimpleQtCryptor::NoError != er) {
    print((boost::format("\n  FAILED: on encryption: %1\n")
              % (SimpleQtCryptor::Info::errorText(er))).str());
    return false;
  }
  er = dx.decrypt(ct, pt, true);
  if (SimpleQtCryptor::NoError != er) {
    print((boost::format("\n  FAILED: on decryption: %1\n")
              % (SimpleQtCryptor::Info::errorText(er))).str());
    return false;
  }

  if (data.size() != pt.size()) {
    print((boost::format("\n  FAILED: wrong size of decrypted data (%1 not %2)\n")
              % (pt.size())
              % (data.size())).str());
    return false;
  }

  if (qChecksum((uint8_t *)data.data(), data.size()) !=
      qChecksum((uint8_t *)pt.data(), pt.size())) {

    std::ofstream o1("out1.txt", std::ios_base::binary);
    std::ofstream o2("out2.txt", std::ios_base::binary);
    o1.write((char*)data.data(), data.size());
    o2.write((char*)pt.data(), pt.size());
    print((boost::format("\n  FAILED: decryption did not recover original data\n")).str());
    return false;
  }

  print((boost::format(" passed\n")).str());
  return true;
}

bool SelfTest::test3_decryptorwiz(std::shared_ptr<SimpleQtCryptor::Key> *kl,
                                  int kc, const std::vector<uint8_t> &data,
                                  SimpleQtCryptor::Algorithm a,
                                  SimpleQtCryptor::Mode m) {
  SimpleQtCryptor::Encryptor ex(kl[std::rand() % kc], a, m,
                                SimpleQtCryptor::NoChecksum);
  std::vector<uint8_t> ct;
  std::vector<uint8_t> cttmp;
  std::vector<uint8_t> pt;
  std::vector<uint8_t> pttmp;
  SimpleQtCryptor::Error er;
  std::shared_ptr<SimpleQtCryptor::Decryptor> dx;

  // qDebug() << "SIZE OF DATA=" << (data.size());
  // qDebug() << "---encrypt---";
  int tmpl = data.size();
  int tmpp = 0;
  int tmpx = 0;
  do {
    tmpx = std::min(tmpl - tmpp, std::rand() % 80);
    er = ex.encrypt(std::vector<uint8_t>(data.begin() + tmpp, data.begin() + tmpp + tmpx), cttmp, (tmpl == tmpp + tmpx));
    if (SimpleQtCryptor::NoError != er) {
      print((boost::format("\n  FAILED: on encryption bytes %1%-%2%: %3%\n")
                % (tmpp)
                % (tmpp + tmpx - 1)
                % (SimpleQtCryptor::Info::errorText(er))).str());
      return false;
    }
    tmpp += tmpx;
    ct.insert(ct.end(), cttmp.begin(), cttmp.end());
    cttmp.clear();
  } while (tmpp < tmpl);

  SimpleQtCryptor::DecryptorWizard dw(kl[0], SimpleQtCryptor::DetectAlgorithm,
                                      SimpleQtCryptor::DetectMode);
  for (int i = 1; i < kc; i++) {
    dw.addParameters(kl[i], a, m);
  }

  // qDebug() << "SIZE OF CT=" << (ct.size());
  // qDebug() << "---decrypt---";
  tmpl = ct.size();
  tmpp = 0;
  tmpx = 0;
  er = dw.decrypt(std::vector<uint8_t>(ct.begin(), ct.begin() + 16), pttmp, dx, false);
  if (SimpleQtCryptor::ErrorNotEnoughData != er) {
    print(
        (boost::format("\n  FAILED: not handling too little data correctly, got %1%\n")
            % (SimpleQtCryptor::Info::errorText(er))).str());
    return false;
  }
  pttmp.clear();
  tmpx = std::min(80 + std::rand() % 80, tmpl);
  er = dw.decrypt(std::vector<uint8_t>(ct.begin(), ct.begin() + tmpx), pt, dx, false);
  if (SimpleQtCryptor::NoError != er) {
    print((boost::format("\n  FAILED: on decrypting data, got %1%\n")
              % (SimpleQtCryptor::Info::errorText(er))).str());
    return false;
  }
  tmpp += tmpx;
  // qDebug() << "---decrypt (2)---";
  do {
    tmpx = std::min(tmpl - tmpp, std::rand() % 80);
    er = dx->decrypt(std::vector<uint8_t>(ct.begin() + tmpp, ct.begin() + tmpp + tmpx), pttmp, (tmpl == tmpx + tmpp));
    if (SimpleQtCryptor::NoError != er) {
      print((boost::format("\n  FAILED: on decrypting bytes %1%-%2%: %3%\n")
                % (tmpp)
                % (tmpp + tmpx - 1)
                % (SimpleQtCryptor::Info::errorText(er))).str());
      return false;
    }
    tmpp += tmpx;
    pt.insert(pt.end(), pttmp.begin(), pttmp.end());
    pttmp.clear();
  } while (tmpp < tmpl);

  if (data.size() != pt.size()) {
    print((boost::format("\n  FAILED: wrong size of decrypted data (%1% not %2%)\n")
              % (pt.size())
              % (data.size())).str());
    return false;
  }

  if (qChecksum((uint8_t *)data.data(), data.size()) !=
      qChecksum((uint8_t *)pt.data(), pt.size())) {
    print((boost::format("\n  FAILED: decryption did not recover original data\n")).str());
    return false;
  }

  print((boost::format(" passed\n")).str());
  return true;
}

bool SelfTest::test(std::vector<uint8_t> &testdata, std::string *outmsg) {
  outString = outmsg;
  outFile = 0;
  return test(testdata);
}

bool SelfTest::test(std::vector<uint8_t> &testdata, std::ostream *outmsg) {
  outString = 0;
  outFile = outmsg;
  return test(testdata);
}

bool SelfTest::test(std::vector<uint8_t> &testdata) {
  if (testdata.empty()) {
    print((boost::format("Warning, testdata was empty\n")).str());
  }

  std::vector<uint8_t> testdata16 = std::vector<uint8_t>(testdata.begin(), testdata.begin() + 
    std::min(16, (int)testdata.size()));
  if (testdata16.size() < 16) {
    std::vector<uint8_t> tmp(16 - testdata.size(), 0);
    testdata16.insert(testdata16.end(), tmp.begin(), tmp.end());;
  }

  {
    int rv = qChecksum(testdata.data(), std::min(4096, (int)testdata.size()));
    std::srand(rv);
    print((boost::format("Random seed for this input file: %1%\n") % (rv)).str());
  }

  print((boost::format("Setting up keys...\n")).str());
  print((boost::format("  - zero key\n")).str());
  std::shared_ptr<SimpleQtCryptor::Key> keyZero(new SimpleQtCryptor::Key());
  print((boost::format("  - based on String (randomized)\n")).str());
  std::shared_ptr<SimpleQtCryptor::Key> keyStr(
      new SimpleQtCryptor::Key(getRandomString()));
  print((boost::format("  - based on Contents of testfile\n")).str());
  std::shared_ptr<SimpleQtCryptor::Key> keyBuf(new SimpleQtCryptor::Key(
      std::vector<uint8_t>(testdata.begin(), testdata.begin() + std::min((int)testdata.size(), std::rand() % 64))));
  print((boost::format("done\n")).str());

  std::shared_ptr<SimpleQtCryptor::Key> keyAll[3];
  keyAll[0] = keyZero;
  keyAll[1] = keyStr;
  keyAll[2] = keyBuf;

  bool ok = true;
  bool done = false;
  int testn = 1;
  while (ok && !done) {
    switch (testn) {
      case (0):
        done = true;
        break;
      case (1):
        print((boost::format("=== KEYS ===\n")).str());
        print((boost::format("%1% Expand RC5 Key:")% testn).str());
        ok = test_key_zero_expand(keyZero);
        testn = 2;
        break;
      case (2):
        print((boost::format("%1% Expand Serpent Key:")% testn).str());
        ok = test_key_zero_expand_spt(keyZero);
        testn = 3;
        break;
      case (3):
        keyStr->expandKeyRc532();
        keyStr->expandKeyRc564();
        keyBuf->expandKeyRc532();
        keyBuf->expandKeyRc564();
        keyStr->expandKeySerpent();
        keyBuf->expandKeySerpent();
        testn = 5;
        break;
      case (5):
        print((boost::format("%1% S-Field (RC5 32bit):")% testn).str());
        ok = test_key_zero_s32(keyZero);
        testn = 6;
        break;
      case (6):
        print((boost::format("%1% S-Field (RC5 64bit):")% testn).str());
        ok = test_key_zero_s64(keyZero);
        testn = 7;
        break;
      case (7):
        print((boost::format("%1% S-Field (Serpent):")% testn).str());
        ok = test_key_zero_spt(keyZero);
        testn = 11;
        break;
      case (11):
        print((boost::format("=== LEVEL 1 ===\n")).str());
        print((boost::format("%1% RC5 Encrypt Zero (32bit):")% testn).str());
        ok = test_rc5_32_encrypt_8b(keyZero, (uint8_t *)(std::vector<uint8_t>(8, 0).data()),
                                    33590);
        testn = 12;
        break;
      case (12):
        print((boost::format("%1% RC5 Encrypt Zero (64bit):")% testn).str());
        ok = test_rc5_64_encrypt_16b(
            keyZero, (uint8_t *)(std::vector<uint8_t>(16, 0).data()), 25205);
        testn = 13;
        break;
      case (13):
        print((boost::format("%1% RC5 Decrypt Zero (32bit):")% testn).str());
        ok = test_rc5_32_decrypt_8b(keyZero, (uint8_t *)(std::vector<uint8_t>(8, 0).data()),
                                    16263);
        testn = 14;
        break;
      case (14):
        print((boost::format("%1% RC5 Decrypt Zero (64bit):")% testn).str());
        ok = test_rc5_64_decrypt_16b(
            keyZero, (uint8_t *)(std::vector<uint8_t>(16, 0).data()), 27423);
        testn = 15;
        break;
      case (15):
        print((boost::format("%1% Serpent Encrypt Zero:")% testn).str());
        ok = test_serpent_encrypt_16b(
            keyZero, (uint8_t *)(std::vector<uint8_t>(16, 0).data()), 12239);
        testn = 16;
        break;
      case (16):
        print((boost::format("%1% Serpent Decrypt Zero:")% testn).str());
        ok = test_serpent_decrypt_16b(
            keyZero, (uint8_t *)(std::vector<uint8_t>(16, 0).data()), 49930);
        testn = 21;
        break;
      case (21):
        print((boost::format("%1% RC5 Encrypt & Decrypt first block of file (32bit):")
                  % testn).str());
        ok = test_rc5_32_encrypt_decrypt_8b(keyZero,
                                            (uint8_t *)(testdata16.data()));
        testn = 22;
        break;
      case (22):
        print((boost::format("%1% RC5 Encrypt & Decrypt first block of file (64bit):")
                  % testn).str());
        ok = test_rc5_64_encrypt_decrypt_16b(keyZero,
                                             (uint8_t *)(testdata16.data()));
        testn = 23;
        break;
      case (23):
        print((boost::format("%1% Serpent Encrypt & Decrypt first block of file:")
                  % testn).str());
        ok = test_serpent_encrypt_decrypt_16b(keyZero,
                                              (uint8_t *)(testdata16.data()));
        testn = 31;
        break;
      case (31):
        print((boost::format("=== LEVEL 2 ===\n")).str());
        print((boost::format("%1% RC5 CBC Encrypt & Decrypt entire file (32bit):")
                  % testn).str());
        ok = test2_CBC_encrypt_decrypt(keyAll[std::rand() % 3], testdata,
                                       SimpleQtCryptor::RC5_32_32_20);
        testn = 32;
        break;
      case (32):
        print((boost::format("%1% RC5 CBC Encrypt & Decrypt entire file (64bit):")
                  % testn).str());
        ok = test2_CBC_encrypt_decrypt(keyAll[std::rand() % 3], testdata,
                                       SimpleQtCryptor::RC5_64_32_20);
        testn = 33;
        break;
      case (33):
        print((boost::format("%1% RC5 CFB Encrypt & Decrypt entire file (32bit):")
                  % testn).str());
        ok = test2_CFB_encrypt_decrypt(keyAll[std::rand() % 3], testdata,
                                       SimpleQtCryptor::RC5_32_32_20);
        testn = 34;
        break;
      case (34):
        print((boost::format("%1% RC5 CFB Encrypt & Decrypt entire file (64bit):")
                  % testn).str());
        ok = test2_CFB_encrypt_decrypt(keyAll[std::rand() % 3], testdata,
                                       SimpleQtCryptor::RC5_64_32_20);
        testn = 35;
        break;
      case (35):
        print((boost::format("%1% Serpent CBC Encrypt & Decrypt entire file:")
                  % testn).str());
        ok = test2_CBC_encrypt_decrypt(keyAll[std::rand() % 3], testdata,
                                       SimpleQtCryptor::SERPENT_32);
        testn = 36;
        break;
      case (36):
        print((boost::format("%1% Serpent CFB Encrypt & Decrypt entire file:")
                  % testn).str());
        ok = test2_CFB_encrypt_decrypt(keyAll[std::rand() % 3], testdata,
                                       SimpleQtCryptor::SERPENT_32);
        testn = 41;
        break;
      case (41):
        print((boost::format("%1% RC5 CBC Encrypt in pieces (32bit):")% testn).str());
        ok = test2_encrypt_decrypt_pieceByPiece(keyAll[std::rand() % 3], testdata,
                                                SimpleQtCryptor::RC5_32_32_20,
                                                SimpleQtCryptor::ModeCBC);
        testn = 42;
        break;
      case (42):
        print((boost::format("%1% RC5 CBC Encrypt in pieces (64bit):")% testn).str());
        ok = test2_encrypt_decrypt_pieceByPiece(keyAll[std::rand() % 3], testdata,
                                                SimpleQtCryptor::RC5_64_32_20,
                                                SimpleQtCryptor::ModeCBC);
        testn = 43;
        break;
      case (43):
        print((boost::format("%1% RC5 CFB Encrypt in pieces (32bit):")% testn).str());
        ok = test2_encrypt_decrypt_pieceByPiece(keyAll[std::rand() % 3], testdata,
                                                SimpleQtCryptor::RC5_32_32_20,
                                                SimpleQtCryptor::ModeCFB);
        testn = 44;
        break;
      case (44):
        print((boost::format("%1% RC5 CFB Encrypt in pieces (64bit):")% testn).str());
        ok = test2_encrypt_decrypt_pieceByPiece(keyAll[std::rand() % 3], testdata,
                                                SimpleQtCryptor::RC5_64_32_20,
                                                SimpleQtCryptor::ModeCFB);
        testn = 45;
        break;
      case (45):
        print((boost::format("%1% Serpent CBC Encrypt in pieces:")% testn).str());
        ok = test2_encrypt_decrypt_pieceByPiece(keyAll[std::rand() % 3], testdata,
                                                SimpleQtCryptor::SERPENT_32,
                                                SimpleQtCryptor::ModeCBC);
        testn = 46;
        break;
      case (46):
        print((boost::format("%1% Serpent CFB Encrypt in pieces:")% testn).str());
        ok = test2_encrypt_decrypt_pieceByPiece(keyAll[std::rand() % 3], testdata,
                                                SimpleQtCryptor::SERPENT_32,
                                                SimpleQtCryptor::ModeCFB);
        testn = 51;
        break;
      case (51):
        print((boost::format("=== LEVEL 3 ===\n")).str());
        print((boost::format("%1% RC5 CBC Encrypt & Decrypt entire file (32bit):")
                  % testn).str());
        ok = test3_encrypt_decrypt(keyAll[std::rand() % 3], testdata,
                                   SimpleQtCryptor::RC5_32_32_20,
                                   SimpleQtCryptor::ModeCBC);
        testn = 52;
        break;
      case (52):
        print((boost::format("%1% RC5 CBC Encrypt & Decrypt entire file (64bit):")
                  % testn).str());
        ok = test3_encrypt_decrypt(keyAll[std::rand() % 3], testdata,
                                   SimpleQtCryptor::RC5_64_32_20,
                                   SimpleQtCryptor::ModeCBC);
        testn = 53;
        break;
      case (53):
        print((boost::format("%1% RC5 CFB Encrypt & Decrypt entire file (32bit):")
                  % testn).str());
        ok = test3_encrypt_decrypt(keyAll[std::rand() % 3], testdata,
                                   SimpleQtCryptor::RC5_32_32_20,
                                   SimpleQtCryptor::ModeCFB);
        testn = 54;
        break;
      case (54):
        print((boost::format("%1% RC5 CFB Encrypt & Decrypt entire file (64bit):")
                  % testn).str());
        ok = test3_encrypt_decrypt(keyAll[std::rand() % 3], testdata,
                                   SimpleQtCryptor::RC5_64_32_20,
                                   SimpleQtCryptor::ModeCFB);
        testn = 55;
        break;
      case (55):
        print((boost::format("%1% Serpent CBC Encrypt & Decrypt entire file:")
                  % testn).str());
        ok = test3_encrypt_decrypt(keyAll[std::rand() % 3], testdata,
                                   SimpleQtCryptor::SERPENT_32,
                                   SimpleQtCryptor::ModeCBC);
        testn = 56;
        break;
      case (56):
        print((boost::format("%1% Serpent CFB Encrypt & Decrypt entire file:")
                  % testn).str());
        ok = test3_encrypt_decrypt(keyAll[std::rand() % 3], testdata,
                                   SimpleQtCryptor::SERPENT_32,
                                   SimpleQtCryptor::ModeCFB);
        testn = 61;
        break;
      case (61):
        print((boost::format("%1% RC5 CBC Encrypt (32bit) - try DecryptorWizard:")
                  % testn).str());
        ok = test3_decryptorwiz(keyAll, 3, testdata,
                                SimpleQtCryptor::RC5_32_32_20,
                                SimpleQtCryptor::ModeCBC);
        testn = 62;
        break;
      case (62):
        print((boost::format("%1% RC5 CBC Encrypt (64bit) - try DecryptorWizard:")
                  % testn).str());
        ok = test3_decryptorwiz(keyAll, 3, testdata,
                                SimpleQtCryptor::RC5_64_32_20,
                                SimpleQtCryptor::ModeCBC);
        testn = 63;
        break;
      case (63):
        print((boost::format("%1% RC5 CFB Encrypt (32bit) - try DecryptorWizard:")
                  % testn).str());
        ok = test3_decryptorwiz(keyAll, 3, testdata,
                                SimpleQtCryptor::RC5_32_32_20,
                                SimpleQtCryptor::ModeCFB);
        testn = 64;
        break;
      case (64):
        print((boost::format("%1% RC5 CFB Encrypt (64bit) - try DecryptorWizard:")
                  % testn).str());
        ok = test3_decryptorwiz(keyAll, 3, testdata,
                                SimpleQtCryptor::RC5_32_32_20,
                                SimpleQtCryptor::ModeCFB);
        testn = 65;
        break;
      case (65):
        print((boost::format("%1% Serpent CBC Encrypt - try DecryptorWizard:")
                  % testn).str());
        ok =
            test3_decryptorwiz(keyAll, 3, testdata, SimpleQtCryptor::SERPENT_32,
                               SimpleQtCryptor::ModeCBC);
        testn = 66;
        break;
      case (66):
        print((boost::format("%1% Serpent CFB Encrypt - try DecryptorWizard:")
                  % testn).str());
        ok =
            test3_decryptorwiz(keyAll, 3, testdata, SimpleQtCryptor::SERPENT_32,
                               SimpleQtCryptor::ModeCFB);
        testn = 0;
        break;
      default:
        print((boost::format("Unexpected error while testing (1)\n")).str());
        ok = false;
    }
  }

  if (ok) {
    print((boost::format("PASSED - you may try another testfile\n")).str());
  } else {
    print((boost::format("FAILED - something is wrong - dont use SimpleQtCryptor!\n")).str());
  }
  return ok;
}

// SERPENT TESTS

}  // namespace SimpleQtCryptor
