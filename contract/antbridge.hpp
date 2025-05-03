#pragma once

#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <eosio/singleton.hpp>
#include <eosio/time.hpp>

/*/
AntBridge - Cross-Chain Token Bridge Contract
A secure and efficient bridge for transferring tokens between different blockchains
/*/

using namespace std;
using namespace eosio;

CONTRACT antbridge : public contract
{
public:
    using contract::contract;

    // === Data Structures === //

    // --- Bridgers Table --- //
    TABLE bridgers {
        name user_domestic;
        name user_foreign;
        asset sent_to_foreign;
        asset received;
        name chain_foreign;
        name contract_foreign;
        symbol token_symbol_domestic;
        symbol token_symbol_foreign;
        uint32_t last_send_timestamp;

        uint64_t primary_key() const { return user_domestic.value; }
        uint64_t by_foreign() const { return user_foreign.value; }
        uint64_t by_chain() const { return chain_foreign.value; }
    };

    // --- Config Table (Singleton) --- //
    TABLE config {
        bool all_lock_frozen;
        bool all_unlock_frozen;
        name admin_contract;

        uint64_t primary_key() const { return 0; }
    };

    // --- Tokens Table --- //
    TABLE tokens {
        uint64_t token_id;
        name token_contract_foreign;
        name token_contract_domestic;
        symbol token_symbol_domestic;
        symbol token_symbol_foreign;
        name chain_domestic;
        name chain_foreign;
        bool lock_frozen;
        bool unlock_frozen;

        uint64_t primary_key() const { return token_id; }
        uint64_t by_foreign_contract() const { return token_contract_foreign.value; }
        uint64_t by_domestic_contract() const { return token_contract_domestic.value; }
    };

    // --- Blockchains Table --- //
    TABLE blockchains {
        name chain_name;
        name bridge_contract;
        bool enabled;

        uint64_t primary_key() const { return chain_name.value; }
    };

    // --- Log Tables --- //
    // -- Lock Log Table -- //
    TABLE log_lock {
        uint64_t id;
        name chain_sender;
        name user_sender;
        uint64_t token_id;
        asset amount;

        uint64_t primary_key() const { return id; }
        uint64_t by_chain() const { return chain_sender.value; }
        uint64_t by_user() const { return user_sender.value; }
    };

    // -- Claim Log Table -- //
    TABLE log_claim {
        uint64_t id;
        checksum256 tx_id;
        name chain_sender;
        name user_sender;
        uint64_t token_id;
        asset amount;

        uint64_t primary_key() const { return id; }
        checksum256 by_tx_id() const { return tx_id; }
        uint64_t by_chain() const { return chain_sender.value; }
        uint64_t by_user() const { return user_sender.value; }
    };

    // === Multi-index Declarations === //
    typedef multi_index<"bridgers"_n, bridgers,
        indexed_by<"byforeign"_n, const_mem_fun<bridgers, uint64_t, &bridgers::by_foreign>>,
        indexed_by<"bychain"_n, const_mem_fun<bridgers, uint64_t, &bridgers::by_chain>>
    > bridgers_t;

    typedef singleton<"config"_n, config> config_singleton;
    
    typedef multi_index<"tokens"_n, tokens,
        indexed_by<"byforeign"_n, const_mem_fun<tokens, uint64_t, &tokens::by_foreign_contract>>,
        indexed_by<"bydomestic"_n, const_mem_fun<tokens, uint64_t, &tokens::by_domestic_contract>>
    > tokens_t;

    typedef multi_index<"blockchains"_n, blockchains> blockchains_t;

    typedef multi_index<"loglock"_n, log_lock,
        indexed_by<"bychain"_n, const_mem_fun<log_lock, uint64_t, &log_lock::by_chain>>,
        indexed_by<"byuser"_n, const_mem_fun<log_lock, uint64_t, &log_lock::by_user>>
    > log_lock_t;

    typedef multi_index<"logclaim"_n, log_claim,
        indexed_by<"bytxid"_n, const_mem_fun<log_claim, checksum256, &log_claim::by_tx_id>>,
        indexed_by<"bychain"_n, const_mem_fun<log_claim, uint64_t, &log_claim::by_chain>>,
        indexed_by<"byuser"_n, const_mem_fun<log_claim, uint64_t, &log_claim::by_user>>
    > log_claim_t;

    // === Actions === //
    // -- Core Bridge Actions -- //
    ACTION lock(const name& user_domestic, const name& user_foreign, const uint64_t& token_id, const asset& quantity);
    ACTION claim(const name& user_domestic, const name& user_foreign, const uint64_t& token_id, const asset& quantity, const checksum256& tx_id);
    
    // -- Token Management Actions -- //
    ACTION addtoken(const name& token_contract_foreign, const name& token_contract_domestic, const symbol& token_symbol_domestic, const symbol& token_symbol_foreign, const name& chain_foreign, const name& chain_domestic);
    ACTION togglelock(const uint64_t& token_id, const bool& freeze);
    ACTION toggleunlock(const uint64_t& token_id, const bool& freeze);
    
    // -- Admin Actions -- //
    ACTION setadmin(const name& new_admin);
    ACTION addchain(const name& chain_name, const name& bridge_contract);
    ACTION togglechain(const name& chain_name, const bool& enabled);
    ACTION freezeall(const bool& lock_frozen, const bool& unlock_frozen);
    ACTION cleanuplock(const uint64_t& id);
    ACTION cleanupclaim(const uint64_t& id);
    
    // -- Transfer Handler -- //
    ACTION ontransfer(const name& from, const name& to, const asset& quantity, const string& memo);

    // === Helper Functions === //
    // -- Authorization Helpers -- //
    void check_admin_auth();
    
    // -- Validation Helpers -- //
    void validate_token(const uint64_t& token_id);
    void validate_chain(const name& chain_name);
    void validate_quantity(const asset& quantity);
    
    // -- Logging Helpers -- //
    void log_lock_event(const name& chain_sender, const name& user_sender, const uint64_t& token_id, const asset& amount);
    void log_claim_event(const name& chain_sender, const name& user_sender, const uint64_t& token_id, const asset& amount, const checksum256& tx_id);
}; 