#pragma once
#include <string>
#include <vector>
#include "json.hpp"

struct Credential {
    std::string site;
    std::string username;
    std::string password;
};

class VaultManager {
private:
    std::vector<Credential> credentials;
    std::string vaultFile = "vault.dat";
    std::string masterPassword;

    void load();
    void save();
    std::vector<unsigned char> deriveKey(unsigned char* salt);
    bool verifyMasterPassword(unsigned char* salt, const unsigned char* hash);

public:
    VaultManager(const std::string& master);
    void addCredential(const Credential& cred);
    void viewAll();
    void search(const std::string& site);
    void deleteCredential(const std::string& site);
    void clearAll();
    std::string generatePassword(int length = 12, bool useSymbols = true);
    std::string auditPassword(const std::string& password);
    void auditPasswordColored(const std::string& password);
    const std::vector<Credential>& getCredentials() const { return credentials; }
};