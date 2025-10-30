#include "vault.h"
#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include <conio.h> // Windows: _getch for hidden input
#include <stdexcept>

// Hidden password input (no echo)
std::string get_hidden_input(const std::string &prompt)
{
    std::cout << prompt;
    std::string input;
    char ch;
    while ((ch = _getch()) != '\r')
    { // Enter ends input
        if (ch == '\b' && !input.empty())
        { // Backspace
            input.pop_back();
            std::cout << "\b \b"; // Erase char
        }
        else if (ch != '\b')
        {
            input += ch;
            std::cout << '*'; // Show asterisk
        }
    }
    std::cout << std::endl;
    return input;
}

// Print entry nicely
void print_entry(const Entry &e)
{
    if (e.id == 0)
    {
        std::cout << "Entry not found." << std::endl;
        return;
    }
    std::cout << "Site: " << e.site << std::endl;
    std::cout << "Username: " << e.username << std::endl;
    std::cout << "Password: " << e.password << std::endl;
}

int main()
{
    try
    {
        Vault vault;
        if (!vault.init_db())
        {
            std::cerr << "Failed to initialize database." << std::endl;
            return 1;
        }

        // Unlock or first-time setup
        std::string master_pw;
        std::string derived_key_hex;
        std::cout << "=== Password Vault CLI ===" << std::endl;

        if (!vault.is_initialized())
        {
            std::cout << "First-time setup: Create a master password." << std::endl;
            while (true)
            {
                std::string pw1 = get_hidden_input("Create Master Password: ");
                std::string pw2 = get_hidden_input("Confirm Master Password: ");
                if (pw1.empty())
                {
                    std::cout << "Password cannot be empty." << std::endl;
                    continue;
                }
                if (pw1 != pw2)
                {
                    std::cout << "Passwords do not match. Try again." << std::endl;
                    continue;
                }
                master_pw = pw1;
                break;
            }
            if (!vault.setup_vault(master_pw) || !vault.unlock(master_pw, derived_key_hex))
            {
                std::cerr << "Failed to set up vault." << std::endl;
                return 1;
            }
            std::cout << "Vault initialized. You are now logged in." << std::endl;
        }
        else
        {
            while (true)
            {
                master_pw = get_hidden_input("Master Password: ");
                if (vault.unlock(master_pw, derived_key_hex))
                {
                    break;
                }
                std::cout << "Invalid master password. Try again." << std::endl;
            }
        }

        // Menu loop
        int choice;
        while (true)
        {
            std::cout << "\n=== Menu ===" << std::endl;
            std::cout << "1. Add entry" << std::endl;
            std::cout << "2. View all entries" << std::endl;
            std::cout << "3. View single entry" << std::endl;
            std::cout << "4. Edit entry" << std::endl;
            std::cout << "5. Delete entry" << std::endl;
            std::cout << "6. Lock & Exit" << std::endl;
            std::cout << "Choice: ";
            std::cin >> choice;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clear buffer

            std::string site, username, password, new_username, new_password;
            switch (choice)
            {
            case 1: // Add
                std::cout << "Site: ";
                std::getline(std::cin, site);
                std::cout << "Username: ";
                std::getline(std::cin, username);
                password = get_hidden_input("Password: ");
                vault.add_entry(derived_key_hex, site, username, password);
                std::cout << "Entry added." << std::endl;
                break;
            case 2: // View all
            {
                auto entries = vault.view_all_entries(derived_key_hex);
                if (entries.empty())
                {
                    std::cout << "No entries." << std::endl;
                }
                else
                {
                    for (const auto &e : entries)
                    {
                        print_entry(e);
                        std::cout << "---" << std::endl;
                    }
                }
            }
            break;
            case 3: // View single
                std::cout << "Site: ";
                std::getline(std::cin, site);
                print_entry(vault.view_single_entry(derived_key_hex, site));
                break;
            case 4: // Edit
                std::cout << "Site: ";
                std::getline(std::cin, site);
                std::cout << "New Username (enter to skip): ";
                std::getline(std::cin, new_username);
                char change_pw;
                std::cout << "Change password? (y/n): ";
                std::cin >> change_pw;
                std::cin.ignore();
                if (change_pw == 'y' || change_pw == 'Y')
                {
                    new_password = get_hidden_input("New Password: ");
                }
                vault.edit_entry(derived_key_hex, site, new_username, new_password);
                std::cout << "Entry updated." << std::endl;
                break;
            case 5: // Delete
                std::cout << "Site: ";
                std::getline(std::cin, site);
                vault.delete_entry(site);
                std::cout << "Entry deleted." << std::endl;
                break;
            case 6: // Exit
                std::cout << "Locked and exiting." << std::endl;
                return 0;
            default:
                std::cout << "Invalid choice." << std::endl;
            }
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
