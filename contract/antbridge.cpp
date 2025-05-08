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
void antbridge::log_lock_event(const name& chain_foreign, const name& chain_domestic, const name& user_foreign, const name& user_domestic, const uint64_t& token_id, const asset& amount) {
    log_lock_t log_lock_table(get_self(), get_self().value);
    log_lock_table.emplace(get_self(), [&](auto& row) {
        row.id = log_lock_table.available_primary_key();
        row.chain_foreign = chain_foreign;
        row.chain_domestic = chain_domestic;
        row.user_foreign = user_foreign;
        row.user_domestic = user_domestic;
        row.token_id = token_id;
        row.amount = amount;
    });
}

void antbridge::log_claim_event(const name& chain_foreign, const name& chain_domestic, const name& user_foreign, const name& user_domestic, const uint64_t& token_id, const asset& amount, const uint64_t& foreign_lock_id) {
    log_claim_t log_claim_table(get_self(), get_self().value);
    log_claim_table.emplace(get_self(), [&](auto& row) {
        row.id = log_claim_table.available_primary_key();
        row.foreign_lock_id = foreign_lock_id;
        row.chain_foreign = chain_foreign;
        row.chain_domestic = chain_domestic;
        row.user_foreign = user_foreign;
        row.user_domestic = user_domestic;
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
        std::make_tuple(user_domestic, get_self(), quantity, std::string("🔒 Lock to ") + token_itr->chain_foreign.to_string() + ": " + quantity.to_string())
    ).send();

    // -- Update Bridgers Table -- //
    bridgers_t bridgers_table(get_self(), get_self().value);
    
    // Check for existing bridger by domestic user, foreign user, chain, and token symbol
    auto by_domestic = bridgers_table.get_index<"bydomestic"_n>();
    auto range_begin = by_domestic.lower_bound(user_domestic.value);
    auto range_end = by_domestic.upper_bound(user_domestic.value);
    
    bool found = false;
    auto bridger_itr = range_begin;
    
    // Look for a match with the same domestic user, foreign user, chain, and token symbol
    while (bridger_itr != range_end) {
        if (bridger_itr->user_foreign == user_foreign && 
            bridger_itr->chain_foreign == token_itr->chain_foreign &&
            bridger_itr->token_symbol_domestic == quantity.symbol) {
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
    log_lock_event(token_itr->chain_foreign, token_itr->chain_domestic, user_foreign, user_domestic, token_itr->token_id, quantity);
}

// --- Claim Action --- //
ACTION antbridge::claim(const name& user_domestic, const name& user_foreign, const uint64_t& token_id, const asset& quantity, const uint64_t& foreign_lock_id) {
    // -- Authorization -- //
    check_admin_auth();  // Only oracle (admin) can call this action

    // -- Validation -- //
    validate_token(token_id);
    validate_quantity(quantity);

    // -- Check if foreign_lock_id already used -- //
    log_claim_t log_claim_table(get_self(), get_self().value);
    auto claim_by_foreign_lock = log_claim_table.get_index<"byfgnlock"_n>();
    auto existing_claim = claim_by_foreign_lock.find(foreign_lock_id);
    check(existing_claim == claim_by_foreign_lock.end(), "🌉 Foreign lock ID already used");

    // -- Check Frozen States -- //
    config_singleton config_table(get_self(), get_self().value);
    auto cfg = config_table.get_or_create(get_self(), config{false, false, get_self()});
    check(!cfg.all_unlock_frozen, "🌉 All unlocks are frozen");

    tokens_t tokens_table(get_self(), get_self().value);
    auto token_itr = tokens_table.find(token_id);
    check(!token_itr->unlock_frozen, "🌉 Token unlock is frozen");

    // -- Update Bridgers Table -- //
    bridgers_t bridgers_table(get_self(), get_self().value);
    
    // Find bridger by domestic user, foreign user, chain, and token symbol
    auto by_domestic = bridgers_table.get_index<"bydomestic"_n>();
    auto range_begin = by_domestic.lower_bound(user_domestic.value);
    auto range_end = by_domestic.upper_bound(user_domestic.value);
    
    bool found = false;
    auto bridger_itr = range_begin;
    
    // Look for a match with the same domestic user, foreign user, chain, and token symbol
    while (bridger_itr != range_end) {
        if (bridger_itr->user_foreign == user_foreign && 
            bridger_itr->chain_foreign == token_itr->chain_foreign &&
            bridger_itr->token_symbol_domestic == quantity.symbol) {
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
        by_domestic.modify(bridger_itr, get_self(), [&](auto& row) {
            row.received += quantity;
        });
    }

    // -- Transfer Tokens -- //
    action(
        permission_level{get_self(), "active"_n},
        token_itr->token_contract_domestic,
        "transfer"_n,
        std::make_tuple(get_self(), user_domestic, quantity, std::string("💰 Claim from ") + token_itr->chain_foreign.to_string() + ": " + quantity.to_string() + " (🔒 ID: " + std::to_string(foreign_lock_id) + ")")
    ).send();

    // -- Log Event -- //
    log_claim_event(token_itr->chain_foreign, token_itr->chain_domestic, user_foreign, user_domestic, token_itr->token_id, quantity, foreign_lock_id);
}

// --- Oracle Claim Update Action --- //
ACTION antbridge::oracleupdate(const uint64_t& log_id, const name& action_context) {
    // -- Authorization -- //
    check_admin_auth();  // Only admin (Oracle) can call this action

    // -- Validate action_context -- //
    check(action_context == "lock"_n || action_context == "claim"_n, "🌉 Invalid action context. Must be 'lock' or 'claim'");

    if (action_context == "lock"_n) {
        // -- Fetch Lock Data -- //
        log_lock_t log_lock_table(get_self(), get_self().value);
        auto lock_itr = log_lock_table.find(log_id);
        check(lock_itr != log_lock_table.end(), "🌉 Lock ID not found in log_lock table");

        // -- Extract Data from Lock Log -- //
        name user_domestic = lock_itr->user_domestic;
        name user_foreign = lock_itr->user_foreign;
        name chain_foreign = lock_itr->chain_foreign;
        asset amount = lock_itr->amount;
        uint64_t token_id = lock_itr->token_id;

        // -- Update Bridgers Table -- //
        bridgers_t bridgers_table(get_self(), get_self().value);
        auto by_domestic = bridgers_table.get_index<"bydomestic"_n>();
        auto range_begin = by_domestic.lower_bound(user_domestic.value);
        auto range_end = by_domestic.upper_bound(user_domestic.value);
        
        bool found = false;
        auto bridger_itr = range_begin;
        
        // Look for a match with the same domestic user, foreign user, chain, and token
        while (bridger_itr != range_end) {
            if (bridger_itr->user_foreign == user_foreign && 
                bridger_itr->chain_foreign == chain_foreign &&
                bridger_itr->token_symbol_domestic == amount.symbol) {
                found = true;
                break;
            }
            bridger_itr++;
        }
        
        check(found, "🌉 Bridger entry not found for user: " + user_domestic.to_string() + ", foreign: " + user_foreign.to_string() + ", chain: " + chain_foreign.to_string() + ", token symbol: " + amount.symbol.code().to_string());
        
        // Update existing bridger entry
        by_domestic.modify(bridger_itr, get_self(), [&](auto& row) {
            row.received += amount;
        });

        // -- Delete Log Entry from log_lock -- //
        log_lock_table.erase(lock_itr);
    } else if (action_context == "claim"_n) {
        // -- Fetch Claim Data -- //
        log_claim_t log_claim_table(get_self(), get_self().value);
        auto claim_itr = log_claim_table.find(log_id);
        check(claim_itr != log_claim_table.end(), "🌉 Claim ID not found in log_claim table");

        // -- Extract Data from Claim Log -- //
        name user_domestic = claim_itr->user_domestic;
        name user_foreign = claim_itr->user_foreign;
        name chain_foreign = claim_itr->chain_foreign;
        asset amount = claim_itr->amount;
        uint64_t token_id = claim_itr->token_id;

        // -- Update Bridgers Table -- //
        bridgers_t bridgers_table(get_self(), get_self().value);
        auto by_domestic = bridgers_table.get_index<"bydomestic"_n>();
        auto range_begin = by_domestic.lower_bound(user_domestic.value);
        auto range_end = by_domestic.upper_bound(user_domestic.value);
        
        bool found = false;
        auto bridger_itr = range_begin;
        
        // Look for a match with the same domestic user, foreign user, chain, and token
        while (bridger_itr != range_end) {
            if (bridger_itr->user_foreign == user_foreign && 
                bridger_itr->chain_foreign == chain_foreign &&
                bridger_itr->token_symbol_domestic == amount.symbol) {
                found = true;
                break;
            }
            bridger_itr++;
        }
        
        check(found, "🌉 Bridger entry not found for user: " + user_domestic.to_string() + ", foreign: " + user_foreign.to_string() + ", chain: " + chain_foreign.to_string() + ", token symbol: " + amount.symbol.code().to_string());
        
        // Update existing bridger entry
        by_domestic.modify(bridger_itr, get_self(), [&](auto& row) {
            row.sent_to_foreign += amount;  // Adjust for claim confirmation if needed
        });

        // -- Delete Log Entry from log_claim -- //
        log_claim_table.erase(claim_itr);
    }
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
    
    // Handle "deposit" memo
    if (memo == "deposit") {
        // Accept transactions with memo "deposit" without further processing
        return;
    }

    // Get the contract that sent the transfer notification
    name token_contract = get_first_receiver();
    
    
    // Parse memo format "chain:user"
    size_t colon_pos = memo.find(':');
    check(colon_pos != string::npos, "🌉 Invalid format. Must use 'chain:user' or 'deposit'");
    
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
    
    // Check for existing bridger by domestic user, foreign user, chain, and token symbol
    auto by_domestic = bridgers_table.get_index<"bydomestic"_n>();
    auto range_begin = by_domestic.lower_bound(from.value);
    auto range_end = by_domestic.upper_bound(from.value);
    
    bool found = false;
    auto bridger_itr = range_begin;
    
    // Look for a match with the same domestic user, foreign user, chain, and token symbol
    while (bridger_itr != range_end) {
        if (bridger_itr->user_foreign == user_foreign && 
            bridger_itr->chain_foreign == chain_foreign &&
            bridger_itr->token_symbol_domestic == quantity.symbol) {
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
    log_lock_event(chain_foreign, token_itr->chain_domestic, user_foreign, from, token_itr->token_id, quantity);
} //END ontransfer

// === Cleanup Actions === //
// --- Cleanup Lock Action --- //
ACTION antbridge::cleanuplock(const uint64_t& id) {
    check_admin_auth();
    
    log_lock_t log_lock_table(get_self(), get_self().value);
    auto lock_itr = log_lock_table.find(id);
    check(lock_itr != log_lock_table.end(), "🌉 Lock log entry not found");
    
    log_lock_table.erase(lock_itr);
}

// --- Cleanup Claim Action --- //
ACTION antbridge::cleanupclaim(const uint64_t& id) {
    check_admin_auth();
    
    log_claim_t log_claim_table(get_self(), get_self().value);
    auto claim_itr = log_claim_table.find(id);
    check(claim_itr != log_claim_table.end(), "🌉 Claim log entry not found");
    
    log_claim_table.erase(claim_itr);
}

// --- Refund Action --- //
ACTION antbridge::refund(const uint64_t& log_lock_id) {
    check_admin_auth();  // Only admin can call this action

    // Fetch log_lock entry
    log_lock_t log_lock_table(get_self(), get_self().value);
    auto lock_itr = log_lock_table.find(log_lock_id);
    check(lock_itr != log_lock_table.end(), "🌉 Lock log entry not found for ID: " + std::to_string(log_lock_id));

    // Extract data from log_lock entry
    name user_domestic = lock_itr->user_domestic;
    name user_foreign = lock_itr->user_foreign;
    name chain_foreign = lock_itr->chain_foreign;
    uint64_t token_id = lock_itr->token_id;
    asset quantity = lock_itr->amount;

    // Remove log_lock entry
    log_lock_table.erase(lock_itr);

    // Update or remove bridger entry
    bridgers_t bridgers_table(get_self(), get_self().value);
    auto by_domestic = bridgers_table.get_index<"bydomestic"_n>();
    auto range_begin = by_domestic.lower_bound(user_domestic.value);
    auto range_end = by_domestic.upper_bound(user_domestic.value);
    bool found = false;
    auto bridger_itr = range_begin;
    while (bridger_itr != range_end) {
        if (bridger_itr->user_foreign == user_foreign && 
            bridger_itr->chain_foreign == chain_foreign && 
            bridger_itr->token_symbol_domestic == quantity.symbol) {
            found = true;
            break;
        }
        bridger_itr++;
    }
    check(found, "🌉 Bridger entry not found for user: " + user_domestic.to_string() + ", foreign: " + user_foreign.to_string() + ", token symbol: " + quantity.symbol.code().to_string());
    if (bridger_itr->sent_to_foreign == quantity && bridger_itr->received.amount == 0) {
        bridgers_table.erase(*bridger_itr);
    } else {
        by_domestic.modify(bridger_itr, get_self(), [&](auto& row) {
            row.sent_to_foreign -= quantity;
        });
    }

    // Return tokens to user
    tokens_t tokens_table(get_self(), get_self().value);
    auto token_itr = tokens_table.find(token_id);
    action(
        permission_level{get_self(), "active"_n},
        token_itr->token_contract_domestic,
        "transfer"_n,
        std::make_tuple(get_self(), user_domestic, quantity, std::string("💸 Refund from ") + chain_foreign.to_string() + ": " + quantity.to_string() + " 🔒# " + std::to_string(log_lock_id))
    ).send();
} 