#include <iostream>
#include <string>
#include "VaultManager.h"
#include "ConsoleColor.h"

int main() {
    std::string masterPassword;
    VaultManager* vault = nullptr;
    int attempts = 0;

    while (attempts < 3) {
        std::cout << "Enter master password: ";
        std::getline(std::cin, masterPassword);

        try {
            vault = new VaultManager(masterPassword);
            break;
        }
        catch (const std::runtime_error& e) {
            std::cout << e.what() << "\n";
            attempts++;
            if (attempts == 3) {
                std::cout << "Too many failed attempts. Exiting.\n";
                return 1;
            }
        }
    }

    int choice;
    do {
        std::cout << "\n===== Password Vault Menu =====\n";
        std::cout << "1. Add Credential\n";
        std::cout << "2. View All Credentials\n";
        std::cout << "3. Search Credentials\n";
        std::cout << "4. Audit Password\n";
        std::cout << "5. Delete Credential\n";
        std::cout << "6. Clear All Credentials\n";
        std::cout << "0. Exit\n";
        std::cout << "Choice: ";
        std::cin >> choice;
        std::cin.ignore();

        switch (choice) {
        case 1: {
            Credential c;
            std::cout << "Site: "; std::getline(std::cin, c.site);
            std::cout << "Username: "; std::getline(std::cin, c.username);
            std::cout << "Password (leave empty to generate): "; std::getline(std::cin, c.password);

            if (c.password.empty()) {
                int len; char symbols;
                std::cout << "Password length: "; std::cin >> len; std::cin.ignore();
                std::cout << "Include symbols? (y/n): "; std::cin >> symbols; std::cin.ignore();
                c.password = vault->generatePassword(len, symbols == 'y' || symbols == 'Y');
                std::cout << "Generated password: " << c.password << "\n";
                std::cout << "Strength: ";
                vault->auditPasswordColored(c.password);
            }

            vault->addCredential(c);
            break;
        }

        case 2:
            std::cout << "\n=== Stored Credentials ===\n";
            for (auto& c : vault->getCredentials()) {
                std::cout << c.site << " | " << c.username << " | " << c.password << " | Strength: ";
                vault->auditPasswordColored(c.password);
            }
            break;

        case 3: {
            std::string site;
            std::cout << "Enter site to search: ";
            std::getline(std::cin, site);
            vault->search(site);
            break;
        }

        case 4: {
            std::string pwd;
            std::cout << "Enter password to audit: ";
            std::getline(std::cin, pwd);
            std::cout << "Strength: ";
            vault->auditPasswordColored(pwd);
            break;
        }

        case 5: {
            std::string site;
            std::cout << "Enter site to delete: ";
            std::getline(std::cin, site);
            vault->deleteCredential(site);
            break;
        }

        case 6:
            vault->clearAll();
            break;

        case 0:
            std::cout << "Exiting vault.\n";
            break;

        default:
            std::cout << "Invalid choice. Try again.\n";
        }

    } while (choice != 0);

    delete vault;
    return 0;
}