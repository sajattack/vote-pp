class Vote {
    const char *sitename;
    const char *username;
    const char *ip;
    const char *timestamp;
    unsigned char encoded[256];
    public:
        Vote(const char *sitename, const char *username, const char *ip, const char *timestamp);
        bool encode(const char *publickey);
        bool send(const char *targetIP, const char *targetPort);
};
