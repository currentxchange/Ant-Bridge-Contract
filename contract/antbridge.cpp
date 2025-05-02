#include "antbridge.hpp"


/*/
Implementation of the AntBridge contract
Handles cross-chain token transfers and bridge management
/*/

// === Helper Functions === //
// --- Authorization Helpers --- //
void antbridge::check_admin_auth() {
    config_singleton config_table(get_self(), get_self().value);
    auto cfg = config_table.get_or_create(get_self(), config{false, false, get_self()});
    require_auth(cfg.admin_contract);
}

// --- Validation Helpers --- //
void antbridge::validate_token(const uint64_t& token_id) {
    tokens_t tokens_table(get_self(), get_self().value);
    auto token_itr = tokens_table.find(token_id);
    check(token_itr != tokens_table.end(), "Token not found");
}

void antbridge::validate_chain(const name& chain_name) {
    blockchains_t blockchains_table(get_self(), get_self().value);
    auto chain_itr = blockchains_table.find(chain_name.value);
    check(chain_itr != blockchains_table.end(), "Chain not found");
    check(chain_itr->enabled, "Chain is disabled");
}

void antbridge::validate_quantity(const asset& quantity) {
    check(quantity.is_valid(), "Invalid quantity");
    check(quantity.amount > 0, "Quantity must be positive");
}

// --- Logging Helpers --- //
void antbridge::log_lock_event(const name& chain_sender, const name& user_sender, const uint64_t& token_id, const asset& amount, const checksum256& tx_id) {
    log_lock_t log_lock_table(get_self(), get_self().value);
    log_lock_table.emplace(get_self(), [&](auto& row) {
        row.chain_sender = chain_sender;
        row.user_sender = user_sender;
        row.token_id = token_id;
        row.amount = amount;
        row.tx_id = tx_id;
    });
}

void antbridge::log_claim_event(const name& chain_sender, const name& user_sender, const uint64_t& token_id, const asset& amount, const checksum256& tx_id) {
    log_claim_t log_claim_table(get_self(), get_self().value);
    log_claim_table.emplace(get_self(), [&](auto& row) {
        row.chain_sender = chain_sender;
        row.user_sender = user_sender;
        row.token_id = token_id;
        row.amount = amount;
        row.tx_id = tx_id;
    });
}

// === Core Bridge Actions === //
// --- Lock Action --- //
ACTION antbridge::lock(const name& user_domestic, const name& user_foreign, const uint64_t& token_id, const asset& quantity) {
    // -- Authorization and Validation -- //
    require_auth(user_domestic);
    validate_token(token_id);
    validate_quantity(quantity);

    // -- Check Frozen States -- //
    config_singleton config_table(get_self(), get_self().value);
    auto cfg = config_table.get_or_create(get_self(), config{false, false, get_self()});
    check(!cfg.all_lock_frozen, "All locks are frozen");

    tokens_t tokens_table(get_self(), get_self().value);
    auto token_itr = tokens_table.find(token_id);
    check(!token_itr->lock_frozen, "Token lock is frozen");

    // -- Transfer Tokens -- //
    action(
        permission_level{user_domestic, "active"_n},
        token_itr->token_contract_domestic,
        "transfer"_n,
        std::make_tuple(user_domestic, get_self(), quantity, string("lock"))
    ).send();

    // -- Update Bridgers Table -- //
    bridgers_t bridgers_table(get_self(), get_self().value);
    auto bridger_itr = bridgers_table.find(user_domestic.value);
    
    if (bridger_itr == bridgers_table.end()) {
        bridgers_table.emplace(get_self(), [&](auto& row) {
            row.user_domestic = user_domestic;
            row.user_foreign = user_foreign;
            row.sent_to_foreign = quantity;
            row.received = asset(0, quantity.symbol);
            row.chain_foreign = token_itr->chain_foreign;
            row.contract_foreign = token_itr->token_contract_foreign;
            row.token_symbol = quantity.symbol;
            row.last_send_timestamp = current_time_point().sec_since_epoch();
        });
    } else {
        bridgers_table.modify(bridger_itr, get_self(), [&](auto& row) {
            row.sent_to_foreign += quantity;
            row.last_send_timestamp = current_time_point().sec_since_epoch();
        });
    }

    // -- Log Event -- //
    log_lock_event(token_itr->chain_foreign, user_domestic, token_id, quantity, checksum256());
}

// --- Claim Action --- //
ACTION antbridge::claim(const name& user_domestic, const name& user_foreign, const uint64_t& token_id, const asset& quantity, const checksum256& tx_id) {
    // -- Authorization and Validation -- //
    require_auth(user_domestic);
    validate_token(token_id);
    validate_quantity(quantity);

    // -- Check Frozen States -- //
    config_singleton config_table(get_self(), get_self().value);
    auto cfg = config_table.get_or_create(get_self(), config{false, false, get_self()});
    check(!cfg.all_unlock_frozen, "All unlocks are frozen");

    tokens_t tokens_table(get_self(), get_self().value);
    auto token_itr = tokens_table.find(token_id);
    check(!token_itr->unlock_frozen, "Token unlock is frozen");

    // -- Update Bridgers Table -- //
    bridgers_t bridgers_table(get_self(), get_self().value);
    auto bridger_itr = bridgers_table.find(user_domestic.value);
    check(bridger_itr != bridgers_table.end(), "Bridger not found");
    check(bridger_itr->received + quantity <= bridger_itr->sent_to_foreign, "Cannot claim more than sent");

    bridgers_table.modify(bridger_itr, get_self(), [&](auto& row) {
        row.received += quantity;
    });

    // -- Transfer Tokens -- //
    action(
        permission_level{get_self(), "active"_n},
        token_itr->token_contract_domestic,
        "transfer"_n,
        std::make_tuple(get_self(), user_domestic, quantity, string("claim"))
    ).send();

    // -- Log Event -- //
    log_claim_event(token_itr->chain_foreign, user_domestic, token_id, quantity, tx_id);
}

// === Token Management Actions === //
// --- Add Token Action --- //
ACTION antbridge::addtoken(const name& token_contract_foreign, const name& token_contract_domestic, const symbol& token_symbol, const name& chain_foreign, const name& chain_domestic) {
    check_admin_auth();
    validate_chain(chain_foreign);
    validate_chain(chain_domestic);

    tokens_t tokens_table(get_self(), get_self().value);
    tokens_table.emplace(get_self(), [&](auto& row) {
        row.token_id = tokens_table.available_primary_key();
        row.token_contract_foreign = token_contract_foreign;
        row.token_contract_domestic = token_contract_domestic;
        row.token_symbol = token_symbol;
        row.chain_domestic = chain_domestic;
        row.chain_foreign = chain_foreign;
        row.lock_frozen = false;
        row.unlock_frozen = false;
    });
}

// --- Toggle Lock Action --- //
ACTION antbridge::togglelock(const uint64_t& token_id, const bool& freeze) {
    check_admin_auth();
    validate_token(token_id);

    tokens_t tokens_table(get_self(), get_self().value);
    auto token_itr = tokens_table.find(token_id);
    tokens_table.modify(token_itr, get_self(), [&](auto& row) {
        row.lock_frozen = freeze;
    });
}

// --- Toggle Unlock Action --- //
ACTION antbridge::toggleunlock(const uint64_t& token_id, const bool& freeze) {
    check_admin_auth();
    validate_token(token_id);

    tokens_t tokens_table(get_self(), get_self().value);
    auto token_itr = tokens_table.find(token_id);
    tokens_table.modify(token_itr, get_self(), [&](auto& row) {
        row.unlock_frozen = freeze;
    });
}

// === Admin Actions === //
// --- Set Admin Action --- //
ACTION antbridge::setadmin(const name& new_admin) {
    check_admin_auth();

    config_singleton config_table(get_self(), get_self().value);
    auto cfg = config_table.get_or_create(get_self(), config{false, false, get_self()});
    cfg.admin_contract = new_admin;
    config_table.set(cfg, get_self());
}

// --- Add Chain Action --- //
ACTION antbridge::addchain(const name& chain_name, const name& bridge_contract) {
    check_admin_auth();

    blockchains_t blockchains_table(get_self(), get_self().value);
    blockchains_table.emplace(get_self(), [&](auto& row) {
        row.chain_name = chain_name;
        row.bridge_contract = bridge_contract;
        row.enabled = true;
    });
}

// --- Toggle Chain Action --- //
ACTION antbridge::togglechain(const name& chain_name, const bool& enabled) {
    check_admin_auth();
    validate_chain(chain_name);

    blockchains_t blockchains_table(get_self(), get_self().value);
    auto chain_itr = blockchains_table.find(chain_name.value);
    blockchains_table.modify(chain_itr, get_self(), [&](auto& row) {
        row.enabled = enabled;
    });
}

// --- Freeze All Action --- //
ACTION antbridge::freezeall(const bool& lock_frozen, const bool& unlock_frozen) {
    check_admin_auth();

    config_singleton config_table(get_self(), get_self().value);
    auto cfg = config_table.get_or_create(get_self(), config{false, false, get_self()});
    cfg.all_lock_frozen = lock_frozen;
    cfg.all_unlock_frozen = unlock_frozen;
    config_table.set(cfg, get_self());
}

// === Transfer Handler === //
// --- On Transfer Action --- //
ACTION antbridge::ontransfer(const name& from, const name& to, const asset& quantity, const string& memo) {
    if (to != get_self()) return;
    
    // -- Parse Memo for Action -- //
    if (memo == "lock") {
        // TODO: Implement cross-chain transfer logic
        // CHECK: Need to verify token contract and quantity
    }
} //END ontransfer 