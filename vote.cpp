//g++ -std=c++0x vote.cpp base64.cpp util.cpp -o vote -lssl -lcrypto -lnsl -lresolv

#include <iostream>
#include <cstring>
#include <openssl/rsa.h>
#include <netdb.h>
#include "util.h"
#include "vote.h"
using namespace std;

    #define OPCODE "VOTE"
    #define ERR_ENCODE_FAILED "Error: The encode function failed.\n"
    #define ERR_SEND_FAILED "Error: The send function failed.\n"

    void printHelpText() {
        cout << "Creates a Votifier vote and sends it to the specified IP address and port" << "\n";
        cout << "vote [publicKey] [sitename] [username] [ip] [timestamp] [targetIP] [targetPort]" << "\n";
    }

    Vote::Vote(const char *sitename, const char *username, const char *ip, const char *timestamp) {
        this->sitename = sitename;
        this->username = username;
        this->ip = ip;
        this->timestamp = timestamp;
    }

    bool Vote::encode(const char *publicKey) {
        //add all the parameters to one char[]
        char temp[256];
        memset(temp, NULL, 256);
        strcat(temp, OPCODE); strcat(temp, "\n");
        strcat(temp, this->sitename); strcat(temp, "\n");
        strcat(temp, this->username); strcat(temp, "\n");
        strcat(temp, this->ip); strcat(temp, "\n");
        strcat(temp, timestamp); strcat(temp, "\n");
        //cout << temp;
        RSA *pubkey = base64ToPubkey(publicKey, 2048);
        if (RSA_public_encrypt(strlen((const char *) temp), (unsigned char *) temp, this->encoded, pubkey, RSA_PKCS1_PADDING)<=0) {
            return false;
        } else {
            return true;
        }
    }

    bool Vote::send(const char *targetIP, const char *targetPort) {
        struct addrinfo hints, *res;
        int sockfd;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(targetIP, targetPort, &hints, &res) != 0) {return false;}
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sockfd == -1) {return false;}
        if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1) {return false;}
        char *c_votifierVersion;
        recv(sockfd, c_votifierVersion, 16, 0);
        std::string votifierVersion(c_votifierVersion);
        //cout << "votifierVersion: " << votifierVersion;
        if (votifierVersion.find("VOTIFIER") == -1) {return false;}
        if (::send(sockfd, this->encoded, 256, 0) == -1) {return false;}
        close(sockfd);
        return true;
    }

    int main(int argc, char *argv[]) {
        if (argc==8) {
            const char *publicKey = argv[1];
            const char *sitename = argv[2];
            const char *username = argv[3];
            const char *ip = argv[4];
            const char *timestamp = argv[5];
            const char *targetIP = argv[6];
            const char *targetPort = argv[7];
            Vote vote = Vote(sitename, username, ip, timestamp);
            if(vote.encode(publicKey)==false) {
                cout << ERR_ENCODE_FAILED;
            }
            if(vote.send(targetIP, targetPort)==false) {
                cout << ERR_SEND_FAILED;
            }
        } else {
            printHelpText();
        }
    }
