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
    check(has_auth(cfg.admin_contract) || has_auth(get_self()), "🌉 Authorization failed. Must be admin or contract");
}

// --- Validation Helpers --- //
void antbridge::validate_token(const uint64_t& token_id) {
    tokens_t tokens_table(get_self(), get_self().value);
    auto token_itr = tokens_table.find(token_id);
    check(token_itr != tokens_table.end(), "🌉 Token not found");
}

void antbridge::validate_chain(const name& chain_name) {
    blockchains_t blockchains_table(get_self(), get_self().value);
    auto chain_itr = blockchains_table.find(chain_name.value);
    check(chain_itr != blockchains_table.end(), "🌉 Chain not found");
    check(chain_itr->enabled, "🌉 Chain is disabled");
}

void antbridge::validate_quantity(const asset& quantity) {
    check(quantity.is_valid(), "🌉 Invalid quantity");
    check(quantity.amount > 0, "🌉 Quantity must be positive");
}

// --- Logging Helpers --- //
void antbridge::log_lock_event(const name& chain_sender, const name& user_sender, const uint64_t& token_id, const asset& amount) {
    log_lock_t log_lock_table(get_self(), get_self().value);
    log_lock_table.emplace(get_self(), [&](auto& row) {
        row.id = log_lock_table.available_primary_key();
        row.chain_sender = chain_sender;
        row.user_sender = user_sender;
        row.token_id = token_id;
        row.amount = amount;
    });
}

void antbridge::log_claim_event(const name& chain_sender, const name& user_sender, const uint64_t& token_id, const asset& amount, const checksum256& tx_id) {
    log_claim_t log_claim_table(get_self(), get_self().value);
    log_claim_table.emplace(get_self(), [&](auto& row) {
        row.id = log_claim_table.available_primary_key();
        row.tx_id = tx_id;
        row.chain_sender = chain_sender;
        row.user_sender = user_sender;
        row.token_id = token_id;
        row.amount = amount;
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
    check(!cfg.all_lock_frozen, "🌉 All locks are frozen");

    tokens_t tokens_table(get_self(), get_self().value);
    auto token_itr = tokens_table.find(token_id);
    check(!token_itr->lock_frozen, "🌉 Token lock is frozen");

    // -- Transfer Tokens -- //
    action(
        permission_level{user_domestic, "active"_n},
        token_itr->token_contract_domestic,
        "transfer"_n,
        std::make_tuple(user_domestic, get_self(), quantity, string("lock"))
    ).send();

    // -- Update Bridgers Table -- //
    bridgers_t bridgers_table(get_self(), get_self().value);
    
    // Check for existing bridger by domestic user, foreign user, and chain
    auto by_domestic = bridgers_table.get_index<"bydomestic"_n>();
    auto range_begin = by_domestic.lower_bound(user_domestic.value);
    auto range_end = by_domestic.upper_bound(user_domestic.value);
    
    bool found = false;
    auto bridger_itr = range_begin;
    
    // Look for a match with the same domestic user, foreign user, and chain
    while (bridger_itr != range_end) {
        if (bridger_itr->user_foreign == user_foreign && 
            bridger_itr->chain_foreign == token_itr->chain_foreign) {
            found = true;
            break;
        }
        bridger_itr++;
    }
    
    if (!found) {
        // Create new bridger entry
        bridgers_table.emplace(get_self(), [&](auto& row) {
            row.id = bridgers_table.available_primary_key();
            row.user_domestic = user_domestic; 
            row.user_foreign = user_foreign;
            row.sent_to_foreign = quantity;
            row.received = asset(0, quantity.symbol);
            row.chain_foreign = token_itr->chain_foreign;
            row.contract_foreign = token_itr->token_contract_foreign;
            row.token_symbol_domestic = token_itr->token_symbol_domestic;
            row.token_symbol_foreign = token_itr->token_symbol_foreign;
            row.last_send_timestamp = current_time_point().sec_since_epoch();
        });
    } else {
        // Update existing bridger entry
        by_domestic.modify(bridger_itr, get_self(), [&](auto& row) {
            row.sent_to_foreign += quantity;
            row.last_send_timestamp = current_time_point().sec_since_epoch();
        });
    }

    // -- Log Event -- //
    log_lock_event(token_itr->chain_foreign, user_domestic, token_id, quantity);
}

// --- Claim Action --- //
ACTION antbridge::claim(const name& user_domestic, const name& user_foreign, const uint64_t& token_id, const asset& quantity, const checksum256& tx_id) {
    // -- Authorization -- //
    check_admin_auth();  // Only oracle (admin) can call this action

    // -- Validation -- //
    validate_token(token_id);
    validate_quantity(quantity);

    // -- Check if tx_id already used -- //
    log_claim_t log_claim_table(get_self(), get_self().value);
    auto claim_by_tx = log_claim_table.get_index<"bytxid"_n>();
    auto existing_claim = claim_by_tx.find(tx_id);
    check(existing_claim == claim_by_tx.end(), "🌉 Transaction ID already used");

    // -- Check Frozen States -- //
    config_singleton config_table(get_self(), get_self().value);
    auto cfg = config_table.get_or_create(get_self(), config{false, false, get_self()});
    check(!cfg.all_unlock_frozen, "🌉 All unlocks are frozen");

    tokens_t tokens_table(get_self(), get_self().value);
    auto token_itr = tokens_table.find(token_id);
    check(!token_itr->unlock_frozen, "🌉 Token unlock is frozen");

    // -- Update Bridgers Table -- //
    bridgers_t bridgers_table(get_self(), get_self().value);
    
    // Find bridger by domestic user, foreign user, and chain
    auto by_domestic = bridgers_table.get_index<"bydomestic"_n>();
    auto range_begin = by_domestic.lower_bound(user_domestic.value);
    auto range_end = by_domestic.upper_bound(user_domestic.value);
    
    bool found = false;
    auto bridger_itr = range_begin;
    
    // Look for a match with the same domestic user, foreign user, and token's chain
    while (bridger_itr != range_end) {
        if (bridger_itr->user_foreign == user_foreign && 
            bridger_itr->chain_foreign == token_itr->chain_foreign) {
            found = true;
            break;
        }
        bridger_itr++;
    }
    
    if (!found) {
        // Create new bridger entry for first-time claim
        bridgers_table.emplace(get_self(), [&](auto& row) {
            row.id = bridgers_table.available_primary_key();
            row.user_domestic = user_domestic;
            row.user_foreign = user_foreign;
            row.sent_to_foreign = asset(0, quantity.symbol);  // No previous sends
            row.received = quantity;  // First claim
            row.chain_foreign = token_itr->chain_foreign;
            row.contract_foreign = token_itr->token_contract_foreign;
            row.token_symbol_domestic = token_itr->token_symbol_domestic;
            row.token_symbol_foreign = token_itr->token_symbol_foreign;
            row.last_send_timestamp = current_time_point().sec_since_epoch();
        });
    } else {
        // Update existing bridger entry
        check(bridger_itr->received + quantity <= bridger_itr->sent_to_foreign, "🌉 Cannot claim more than sent");
        by_domestic.modify(bridger_itr, get_self(), [&](auto& row) {
            row.received += quantity;
        });
    }

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
ACTION antbridge::addtoken(const name& token_contract_foreign, const name& token_contract_domestic, const symbol& token_symbol_domestic, const symbol& token_symbol_foreign, const name& chain_foreign, const name& chain_domestic) {
    check_admin_auth();
    validate_chain(chain_foreign);
    validate_chain(chain_domestic);

    tokens_t tokens_table(get_self(), get_self().value);
    
    // Check for duplicate token configuration
    // Iterate through the table using proper EOSIO iteration pattern
    auto itr = tokens_table.begin();
    while (itr != tokens_table.end()) {
        // Check if the same domestic and foreign token pair already exists
        if (itr->token_contract_domestic == token_contract_domestic && 
            itr->token_symbol_domestic == token_symbol_domestic &&
            itr->token_contract_foreign == token_contract_foreign && 
            itr->token_symbol_foreign == token_symbol_foreign &&
            itr->chain_foreign == chain_foreign) {
            check(false, "🌉 Token with identical domestic and foreign details already exists");
        }
        itr++;
    }
    
    tokens_table.emplace(get_self(), [&](auto& row) {
        row.token_id = tokens_table.available_primary_key();
        row.token_contract_foreign = token_contract_foreign;
        row.token_contract_domestic = token_contract_domestic;
        row.token_symbol_domestic = token_symbol_domestic;
        row.token_symbol_foreign = token_symbol_foreign;
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
[[eosio::on_notify("*::transfer")]] void antbridge::ontransfer(const name& from, const name& to, const asset& quantity, const string& memo) {
    if (to != get_self()) return;
    
    // Get the contract that sent the transfer notification
    name token_contract = get_first_receiver();
    
    // Handle the special case for "deposit" memo
    if (memo == "deposit") {
        // Accept transactions with memo "deposit" without further processing
        return;
    }
    
    // Parse memo format "chain:user"
    size_t colon_pos = memo.find(':');
    check(colon_pos != string::npos, "🌉 Invalid memo format. Expected 'chain:user' or 'deposit'");
    
    name chain_foreign = name(memo.substr(0, colon_pos));
    name user_foreign = name(memo.substr(colon_pos + 1));
    
    // Validate chain exists
    validate_chain(chain_foreign);
    
    // Validate user name format (1-12 chars, only a-z, 1-5, and .)
    string user_str = user_foreign.to_string();
    check(user_str.length() >= 1 && user_str.length() <= 12, "🌉 Foreign account name must be 1-12 characters");
    check(user_str.find_first_not_of("abcdefghijklmnopqrstuvwxyz12345.") == string::npos, "🌉 Foreign account name contains invalid characters");
    check(user_str.back() != '.', "🌉 Foreign account name cannot end with a dot");
    
    // Find token by contract and symbol
    tokens_t tokens_table(get_self(), get_self().value);
    auto token_by_contract = tokens_table.get_index<"bydomestic"_n>();
    auto token_itr = token_by_contract.lower_bound(token_contract.value);
    auto token_end = token_by_contract.upper_bound(token_contract.value);
    
    // Find the specific token with matching domestic symbol
    bool token_found = false;
    while (token_itr != token_end) {
        if (token_itr->token_symbol_domestic == quantity.symbol) {
            token_found = true;
            break;
        }
        token_itr++;
    }
    
    // Check if this is an allowed token
    check(token_found, "🌉 Token contract and symbol combination not allowed");
    
    // Check if locks are frozen
    config_singleton config_table(get_self(), get_self().value);
    auto cfg = config_table.get_or_create(get_self(), config{false, false, get_self()});
    check(!cfg.all_lock_frozen, "🌉 All locks are frozen");
    check(!token_itr->lock_frozen, "🌉 Token lock is frozen");
    
    // Update bridgers table
    bridgers_t bridgers_table(get_self(), get_self().value);
    
    // Check for existing bridger by domestic user, foreign user, and chain
    auto by_domestic = bridgers_table.get_index<"bydomestic"_n>();
    auto range_begin = by_domestic.lower_bound(from.value);
    auto range_end = by_domestic.upper_bound(from.value);
    
    bool found = false;
    auto bridger_itr = range_begin;
    
    // Look for a match with the same domestic user, foreign user, and chain
    while (bridger_itr != range_end) {
        if (bridger_itr->user_foreign == user_foreign && 
            bridger_itr->chain_foreign == chain_foreign) {
            found = true;
            break;
        }
        bridger_itr++;
    }
    
    if (!found) {
        // Create new bridger entry
        bridgers_table.emplace(get_self(), [&](auto& row) {
            row.id = bridgers_table.available_primary_key();
            row.user_domestic = from;
            row.user_foreign = user_foreign;
            row.sent_to_foreign = quantity;
            row.received = asset(0, quantity.symbol);
            row.chain_foreign = chain_foreign;
            row.contract_foreign = token_itr->token_contract_foreign;
            row.token_symbol_domestic = token_itr->token_symbol_domestic;
            row.token_symbol_foreign = token_itr->token_symbol_foreign;
            row.last_send_timestamp = current_time_point().sec_since_epoch();
        });
    } else {
        // Update existing bridger entry
        by_domestic.modify(bridger_itr, get_self(), [&](auto& row) {
            row.sent_to_foreign += quantity;
            row.last_send_timestamp = current_time_point().sec_since_epoch();
        });
    }
    
    // Log the lock event
    log_lock_event(token_itr->chain_foreign, from, token_itr->token_id, quantity);
} //END ontransfer

// --- Cleanup Actions --- //
ACTION antbridge::cleanuplock(const uint64_t& id) {
    check_admin_auth();
    
    log_lock_t log_lock_table(get_self(), get_self().value);
    auto lock_itr = log_lock_table.find(id);
    check(lock_itr != log_lock_table.end(), "🌉 Lock log entry not found");
    
    log_lock_table.erase(lock_itr);
}

ACTION antbridge::cleanupclaim(const uint64_t& id) {
    check_admin_auth();
    
    log_claim_t log_claim_table(get_self(), get_self().value);
    auto claim_itr = log_claim_table.find(id);
    check(claim_itr != log_claim_table.end(), "🌉 Claim log entry not found");
    
    log_claim_table.erase(claim_itr);
} 