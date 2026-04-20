#include <iostream>
#include <vector>
#include <string>
#include <unordered_set>

// Simple Bloom filter simulation (bit vector + k hash functions)
class SimpleBloomFilter {
private:
    std::vector<bool> bit_array;
    int m;  // size of bit array (bits)
    int k;  // number of hash functions

public:
    SimpleBloomFilter(int size, int num_hashes) : m(size), k(num_hashes) {
        bit_array.resize(m, false);
    }

    // Simple hash (not cryptographic, just for demo)
    unsigned long simple_hash(const std::string& item, int seed) {
        unsigned long h = 0;
        for (char c : item) {
            h = h * 31 + c;
        }
        h += seed;
        return h % m;
    }

    // Insert an item
    void insert(const std::string& item) {
        for (int i = 0; i < k; ++i) {
            int idx = simple_hash(item, i);
            bit_array[idx] = true;
        }
    }

    // Check if item is in the filter
    bool contains(const std::string& item) {
        for (int i = 0; i < k; ++i) {
            int idx = simple_hash(item, i);
            if (!bit_array[idx]) {
                return false;  // definitely not in the set
            }
        }
        return true;  // probably in the set (maybe false positive)
    }
};

// Helper: run test with n_tests queries and count false positives
void run_test_case(const std::string& app_name,
                   SimpleBloomFilter& filter,
                   const std::vector<std::string>& good_items,
                   const std::vector<std::string>& bad_items) {
    std::cout << "\n=== TEST CASE: " << app_name << " ===\n";

    // 1) Insert all good (real) items into the Bloom filter
    for (const auto& item : good_items) {
        filter.insert(item);
    }

    // 2) Test 100 queries (you can change 100 to 15 if needed)
    int n_queries = 100;
    int n_true_pos = 0;   // correct positive: known item → reported present
    int n_true_neg = 0;   // correct negative: unknown item → reported absent
    int n_false_pos = 0;  // false positive: unknown item → reported present
    int n_false_neg = 0;  // false negative: known item → reported absent (should be 0)

    // We'll do 80% bad + 20% good mix (for statistical behavior)
    for (int i = 0; i < n_queries; ++i) {
        std::string query;
        bool is_good = (i % 5 == 0);  // 1 out of 5 is a good item

        if (is_good && i < good_items.size()) {
            query = good_items[i];
        } else {
            query = "unknown_" + std::to_string(i) + "_" + app_name;
        }

        bool bloom_says_present = filter.contains(query);

        if (is_good) {
            // This is a known item
            if (bloom_says_present) {
                ++n_true_pos;
            } else {
                ++n_false_neg;  // Bloom filter never reports false negatives in theory, but let's count anyway
            }
        } else {
            // This is an unknown item
            if (bloom_says_present) {
                ++n_false_pos;
            } else {
                ++n_true_neg;
            }
        }
    }

    // Print results for this test case
    std::cout << "  - Total queries: " << n_queries << "\n";
    std::cout << "  - True positives: " << n_true_pos << "\n";
    std::cout << "  - True negatives: " << n_true_neg << "\n";
    std::cout << "  - False positives: " << n_false_pos << "\n";
    std::cout << "  - False negatives: " << n_false_neg << "\n";

    double false_pos_rate = (double)n_false_pos / (n_queries - good_items.size());
    double false_neg_rate = (double)n_false_neg / good_items.size();

    std::cout << "  - False positive rate: " << false_pos_rate << "\n";
    std::cout << "  - False negative rate: " << false_neg_rate << "\n";
}

int main() {
    std::cout << "=== Bloom filter experiment for 3 security apps ===\n\n";

    // Application 1: Web-filtering (malware URLs)
    {
        std::cout << "\n\n1. WEB-FILTERING SCENARIO (malware URLs)\n";
        // Bloom filter configured for ~1M URLs, p ≈ 1%
        SimpleBloomFilter bf_web(9600000, 7);  // 9.6M bits, 7 hash functions

        // Known malicious URLs (good items)
        std::vector<std::string> web_good = {
            "malware1.com", "malware2.com", "malware3.com",
            "malware4.com", "malware5.com", "malware6.com",
            "malware7.com", "malware8.com", "malware9.com",
            "malware10.com", "malware11.com", "malware12.com",
            "malware13.com", "malware14.com", "malware15.com"
        };

        // Unknown/safe URLs (bad items for testing)
        std::vector<std::string> web_bad = {
            "safe1.com", "safe2.com", "safe3.com",
            "safe4.com", "safe5.com", "safe6.com",
            "safe7.com", "safe8.com", "safe9.com",
            "safe10.com"
        };

        run_test_case("WEB-FILTERING (malware URLs)", bf_web, web_good, web_bad);
    }

    // Application 2: Spam-filtering (spam IDs)
    {
        std::cout << "\n\n2. SPAM-FILTERING SCENARIO (spam IDs)\n";
        // Bloom filter for 0.5M spam IDs, p ≈ 1%
        SimpleBloomFilter bf_spam(4800000, 7);  // 4.8M bits, 7 hash functions

        std::vector<std::string> spam_good = {
            "spam1@example.com", "spam2@example.com",
            "spam3@example.com", "spam4@example.com",
            "spam5@example.com", "spam6@example.com",
            "spam7@example.com", "spam8@example.com",
            "spam9@example.com", "spam10@example.com",
            "spam11@example.com", "spam12@example.com",
            "spam13@example.com", "spam14@example.com",
            "spam15@example.com"
        };

        std::vector<std::string> spam_bad = {
            "good_user1@example.com", "good_user2@example.com",
            "good_user3@example.com", "good_user4@example.com",
            "good_user5@example.com", "good_user6@example.com",
            "good_user7@example.com", "good_user8@example.com",
            "good_user9@example.com", "good_user10@example.com"
        };

        run_test_case("SPAM-FILTERING (spam IDs)", bf_spam, spam_good, spam_bad);
    }

    // Application 3: Authentication (user IDs)
    {
        std::cout << "\n\n3. AUTHENTICATION SCENARIO (user IDs)\n";
        // Bloom filter for 1M user IDs, p ≈ 0.1%
        SimpleBloomFilter bf_auth(14500000, 10);  // 14.5M bits, 10 hash functions

        std::vector<std::string> auth_good = {
            "user123", "user234", "user345",
            "user456", "user567", "user678",
            "user789", "user890", "user901",
            "user012", "user101", "user202",
            "user303", "user404", "user505"
        };

        std::vector<std::string> auth_bad = {
            "unknown_user1", "unknown_user2",
            "unknown_user3", "unknown_user4",
            "unknown_user5", "unknown_user6",
            "unknown_user7", "unknown_user8",
            "unknown_user9", "unknown_user10"
        };

        run_test_case("AUTHENTICATION (user IDs)", bf_auth, auth_good, auth_bad);
    }

    std::cout << "\n=== ALL EXPERIMENTS FINISHED ===\n";
    return 0;
}