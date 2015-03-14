//#include <iostream>
#include <iomanip>
#include <openssl/rsa.h>
#include <sstream>
#include "base64.h"
using namespace std;

RSA *base64ToPubkey(const char *c_base64, int bitLength) {
    const string base64(c_base64);
    const string ascii = base64_decode(base64);
    stringstream ss;
    for (int i=0; i<ascii.size(); ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(ascii[i]));
    }
    string hex = ss.str();
    string hexModul;
    string hexExpon;
    int modulStart = 66;
    int modulEnd = modulStart+(2*(bitLength/8));
    int exponStart = modulEnd+4;
    int exponEnd = exponStart+6;
    for (int i=modulStart; i<modulEnd; i++) {
        hexModul+=hex[i];
    }
    for (int i=exponStart; i<exponEnd; i++) {
        hexExpon+=hex[i];
    }
//  cout << "hex: " << hex << "\n";
//  cout << "hexModul: " << hexModul << "\n";
//  cout << "hexExpon: " << hexExpon << "\n";
    RSA *pubkey = RSA_new();
    BIGNUM *modul = BN_new();
    BIGNUM *expon = BN_new();
    BN_hex2bn(&modul, (const char *) hexModul.c_str());
    BN_hex2bn(&expon, (const char *) hexExpon.c_str());
    pubkey->n = modul;
    pubkey->e = expon;
    return pubkey;
}
