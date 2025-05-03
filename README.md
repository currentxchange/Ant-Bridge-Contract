# 🌉 Ant-Bridge-Contract
> Private bridging contract for cXc.world - Bridging BLUX and other tokens to Tonomy

## 📋 Overview
This contract serves as a flexible and secure bridge between multiple Antelope-based chains, initially designed for BLUX token transfers between cXc.world and Tonomy, with plans to support additional tokens like PURPLE. 

The contract's architecture enables:
- 🔄 One-to-one token transfers between any two supported chains
- 📐 Polygon patterns for complex multi-chain token flows
- 💎 Support for multiple tokens on each chain
- 🔒 Secure oracle-based validation for all transfers

Each token pair can be configured with:
- Different symbols on each chain
- Custom contract addresses
- Independent freeze controls
- Chain-specific validation rules

The system implements a robust cross-chain token transfer mechanism with comprehensive security measures and oracle-based validation, making it suitable for both simple direct transfers and complex multi-chain token movements.

## 🏗️ Contract Structure

### 🔐 Core Tables

#### Bridgers Table
Tracks user bridge activity and balances:
```cpp
TABLE bridgers {
    name user_domestic;          // EOSIO account name
    name user_foreign;           // Foreign chain account
    asset sent_to_foreign;       // Total sent to foreign chain
    asset received;              // Total received from foreign chain
    name chain_foreign;          // Foreign chain name
    name contract_foreign;       // Foreign token contract
    symbol token_symbol_domestic;// Domestic token symbol
    symbol token_symbol_foreign; // Foreign token symbol
    uint32_t last_send_timestamp;// Last transaction timestamp
}
```

#### Tokens Table
Manages supported token pairs:
```cpp
TABLE tokens {
    uint64_t token_id;           // Unique token identifier
    name token_contract_foreign; // Foreign token contract
    name token_contract_domestic;// Domestic token contract
    symbol token_symbol_domestic;// Domestic token symbol
    symbol token_symbol_foreign; // Foreign token symbol
    name chain_domestic;         // Domestic chain name
    name chain_foreign;          // Foreign chain name
    bool lock_frozen;            // Lock status
    bool unlock_frozen;          // Unlock status
}
```

### 🔄 Core Actions

#### Lock (Send to Foreign Chain)
```cpp
ACTION lock(const name& user_domestic, 
           const name& user_foreign, 
           const uint64_t& token_id, 
           const asset& quantity);
```
- Transfers tokens from user to bridge contract
- Records the transaction in bridgers table
- Logs the lock event

#### Claim (Receive from Foreign Chain)
```cpp
ACTION claim(const name& user_domestic,
            const name& user_foreign,
            const uint64_t& token_id,
            const asset& quantity,
            const checksum256& tx_id);
```
- Oracle-only action to process incoming transfers
- Validates transaction ID to prevent double-claiming
- Transfers tokens to user's account

### 🛡️ Security Features

#### Oracle Authorization
```cpp
void check_admin_auth() {
    config_singleton config_table(get_self(), get_self().value);
    auto cfg = config_table.get_or_create(get_self(), config{false, false, get_self()});
    check(has_auth(cfg.admin_contract) || has_auth(get_self()), 
          "🌉 Authorization failed. Must be admin or contract");
}
```

#### Transaction Validation
```cpp
void validate_token(const uint64_t& token_id) {
    tokens_t tokens_table(get_self(), get_self().value);
    auto token_itr = tokens_table.find(token_id);
    check(token_itr != tokens_table.end(), "🌉 Token not found");
}
```

### 🔧 Management Actions

#### Token Management
```cpp
ACTION addtoken(const name& token_contract_foreign,
               const name& token_contract_domestic,
               const symbol& token_symbol_domestic,
               const symbol& token_symbol_foreign,
               const name& chain_foreign,
               const name& chain_domestic);
```
- Adds new token pairs to the bridge
- Requires admin authorization
- Validates chain existence

#### Freeze Controls
```cpp
ACTION freezeall(const bool& lock_frozen, const bool& unlock_frozen);
ACTION togglelock(const uint64_t& token_id, const bool& freeze);
ACTION toggleunlock(const uint64_t& token_id, const bool& freeze);
```
- Emergency controls for bridge operations
- Can freeze specific tokens or entire bridge
- Admin-only actions

## 🚀 Usage Examples

### Adding BLUX Token
```bash
cleos push action antbridge addtoken '["blux.contract", "blux.eos", "4,BLUX", "4,BLUX", "cxc.world", "tonomy"]' -p antbridge
```

### Locking BLUX Tokens
```bash
cleos push action antbridge lock '["user.eos", "user.tonomy", 1, "100.0000 BLUX"]' -p user.eos
```

### Claiming BLUX Tokens
```bash
cleos push action antbridge claim '["user.eos", "user.tonomy", 1, "100.0000 BLUX", "tx_hash"]' -p oracle.eos
```

## 🔒 Security Considerations

- Oracle-based validation for incoming transfers
- Double-claim prevention using transaction IDs
- Comprehensive freeze controls
- Strict memo format validation
- Chain existence verification
- Token symbol validation

## 📈 Future Enhancements

- Support for additional tokens (PURPLE, etc.)
- Enhanced oracle management
- Fee structure implementation
- Rate limiting mechanisms
- Emergency recovery functions

## 🤝 Contributing
This is a private contract for cXc.world. All contributions and modifications must be approved by the cXc.world team.

## 📄 License
This project is licensed under the [MIT License](LICENSE) - see the [LICENSE](LICENSE) file for details.