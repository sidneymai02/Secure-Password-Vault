#include "VaultManager.h"
#include "ConsoleColor.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <ctime>
#include <algorithm>

using json = nlohmann::json;

constexpr int AES_KEYLEN = 32;
constexpr int AES_IVLEN = 16;
constexpr int SALT_LEN = 16;
constexpr int HASH_LEN = 32;

std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char>& plaintext,
    const unsigned char* key,
    const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, ciphertext_len = 0;

    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char>& ciphertext,
    const unsigned char* key,
    const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, plaintext_len = 0;

    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

std::vector<unsigned char> VaultManager::deriveKey(unsigned char* salt) {
    std::vector<unsigned char> key(AES_KEYLEN);
    if (!PKCS5_PBKDF2_HMAC(masterPassword.c_str(), masterPassword.size(),
        salt, SALT_LEN, 100000, EVP_sha256(),
        AES_KEYLEN, key.data()))
        throw std::runtime_error("PBKDF2 key derivation failed");
    return key;
}

bool VaultManager::verifyMasterPassword(unsigned char* salt, const unsigned char* storedHash) {
    auto key = deriveKey(salt);
    unsigned char hash[HASH_LEN];
    SHA256(key.data(), key.size(), hash);
    return memcmp(hash, storedHash, HASH_LEN) == 0;
}

VaultManager::VaultManager(const std::string& master) : masterPassword(master) {
    srand(time(nullptr));
    load();
}

void VaultManager::load() {
    std::ifstream fin(vaultFile, std::ios::binary);
    if (!fin) return;

    unsigned char salt[SALT_LEN];
    fin.read(reinterpret_cast<char*>(salt), SALT_LEN);

    unsigned char storedHash[HASH_LEN];
    fin.read(reinterpret_cast<char*>(storedHash), HASH_LEN);

    unsigned char iv[AES_IVLEN];
    fin.read(reinterpret_cast<char*>(iv), AES_IVLEN);

    std::vector<unsigned char> enc_data((std::istreambuf_iterator<char>(fin)),
        std::istreambuf_iterator<char>());
    fin.close();

    if (!verifyMasterPassword(salt, storedHash))
        throw std::runtime_error("Wrong master password");

    auto key = deriveKey(salt);
    auto decrypted = aes_decrypt(enc_data, key.data(), iv);
    std::string decrypted_str(decrypted.begin(), decrypted.end());

    credentials.clear();
    if (!decrypted_str.empty()) {
        json vault = json::parse(decrypted_str);
        for (auto& item : vault["accounts"])
            credentials.push_back({ item["site"], item["username"], item["password"] });
    }
}

void VaultManager::save() {
    unsigned char salt[SALT_LEN];
    RAND_bytes(salt, SALT_LEN);

    auto key = deriveKey(salt);

    unsigned char hash[HASH_LEN];
    SHA256(key.data(), key.size(), hash);

    unsigned char iv[AES_IVLEN];
    RAND_bytes(iv, AES_IVLEN);

    json vault;
    for (auto& c : credentials)
        vault["accounts"].push_back({ {"site", c.site}, {"username", c.username}, {"password", c.password} });

    std::string vault_str = vault.dump();
    std::vector<unsigned char> vault_data(vault_str.begin(), vault_str.end());
    auto encrypted = aes_encrypt(vault_data, key.data(), iv);

    std::ofstream fout(vaultFile, std::ios::binary);
    fout.write(reinterpret_cast<const char*>(salt), SALT_LEN);
    fout.write(reinterpret_cast<const char*>(hash), HASH_LEN);
    fout.write(reinterpret_cast<const char*>(iv), AES_IVLEN);
    fout.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    fout.close();
}

void VaultManager::addCredential(const Credential& cred) {
    credentials.push_back(cred);
    save();
    std::cout << "Credential saved!\n";
}

void VaultManager::viewAll() {
    for (auto& c : credentials)
        std::cout << c.site << " | " << c.username << " | " << c.password
        << " | Strength: " << auditPassword(c.password) << "\n";
}

void VaultManager::search(const std::string& site) {
    std::vector<int> matches;
    for (size_t i = 0; i < credentials.size(); ++i) {
        if (credentials[i].site.find(site) != std::string::npos) {
            matches.push_back(i);
            std::cout << matches.size() << ". "
                << credentials[i].site << " | "
                << credentials[i].username << " | "
                << credentials[i].password
                << " | Strength: " << auditPassword(credentials[i].password) << "\n";
        }
    }

    if (matches.empty()) {
        std::cout << "No credentials found matching: " << site << "\n";
        return;
    }

    int choice;
    std::cout << "Enter the number to view full details or 0 to cancel: ";
    std::cin >> choice;
    std::cin.ignore();

    if (choice > 0 && choice <= matches.size()) {
        auto& c = credentials[matches[choice - 1]];
        std::cout << "\nSite: " << c.site
            << "\nUsername: " << c.username
            << "\nPassword: " << c.password
            << "\nStrength: " << auditPassword(c.password) << "\n";
    }
    else {
        std::cout << "Cancelled.\n";
    }
}

void VaultManager::deleteCredential(const std::string& site) {
    std::vector<int> matches;
    for (size_t i = 0; i < credentials.size(); ++i) {
        if (credentials[i].site.find(site) != std::string::npos) {
            matches.push_back(i);
            std::cout << matches.size() << ". " << credentials[i].site
                << " | " << credentials[i].username << "\n";
        }
    }

    if (matches.empty()) {
        std::cout << "No credentials found matching: " << site << "\n";
        return;
    }

    int choice;
    std::cout << "Enter the number of the credential to delete (0 to cancel): ";
    std::cin >> choice;
    std::cin.ignore();

    if (choice > 0 && choice <= matches.size()) {
        char confirm;
        std::cout << "Are you sure you want to delete '"
            << credentials[matches[choice - 1]].site << "'? (y/n): ";
        std::cin >> confirm;
        std::cin.ignore();

        if (confirm == 'y' || confirm == 'Y') {
            credentials.erase(credentials.begin() + matches[choice - 1]);
            save();
            std::cout << "Credential deleted!\n";
        }
        else {
            std::cout << "Operation cancelled.\n";
        }
    }
    else {
        std::cout << "Operation cancelled.\n";
    }
}

void VaultManager::clearAll() {
    char confirm;
    std::cout << "Are you sure you want to DELETE ALL credentials? This cannot be undone! (y/n): ";
    std::cin >> confirm;
    std::cin.ignore();

    if (confirm == 'y' || confirm == 'Y') {
        credentials.clear();
        save();
        std::cout << "All credentials cleared!\n";
    }
    else {
        std::cout << "Operation cancelled.\n";
    }
}

std::string VaultManager::generatePassword(int length, bool useSymbols) {
    const std::string lower = "abcdefghijklmnopqrstuvwxyz";
    const std::string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string digits = "0123456789";
    const std::string symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    std::string pool = lower + upper + digits;
    if (useSymbols) pool += symbols;

    std::string password;
    for (int i = 0; i < length; ++i)
        password += pool[rand() % pool.size()];

    return password;
}

std::string VaultManager::auditPassword(const std::string& password) {
    int score = 0;
    if (password.length() >= 8) score++;
    if (std::any_of(password.begin(), password.end(), ::isdigit)) score++;
    if (std::any_of(password.begin(), password.end(), ::isupper)) score++;
    if (std::any_of(password.begin(), password.end(), ::ispunct)) score++;

    switch (score) {
        case 4: return "Very Strong";
        case 3: return "Strong";
        case 2: return "Medium";
        case 1: return "Weak";
        default: return "Very Weak";
    }
}

void VaultManager::auditPasswordColored(const std::string& password) {
    std::string strength = auditPassword(password);

    if (strength == "Very Strong") setConsoleColor(ConsoleColor::GREEN);
    else if (strength == "Strong") setConsoleColor(ConsoleColor::CYAN);
    else if (strength == "Medium") setConsoleColor(ConsoleColor::YELLOW);
    else if (strength == "Weak") setConsoleColor(ConsoleColor::MAGENTA);
    else setConsoleColor(ConsoleColor::RED);

    std::cout << strength;
    resetConsoleColor();
    std::cout << "\n";
}