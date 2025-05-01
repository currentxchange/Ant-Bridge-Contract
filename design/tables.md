# TABLES

## Bridgers  
Name user_domestic  
Name user_foreign  
Asset sent_to_foreign  
Asset received  
Name chain_foreign  
Name contract_foreign  
Symbol token_symbol  
Uint32 last_send_timestamp  

## Config (Singleton)  
Bool all_lock_frozen  
Bool all_unlock_frozen  
Name admin_contract  

## Tokens  
Uint64 token_id  
Name token_contract_foreign  
Name token_contract_domestic  
Symbol token_symbol  
Name chain_domestic  
Name chain_foreign  
Bool lock_frozen  
Bool unlock_frozen  

## Blockchains  
Name chain_name  
Bool enabled  

## Log_lock  
Name chain_sender  
Name user_sender  
Uint64 token_id  
Asset amount  
Checksum256 tx_id  

## Log_claim  
Name chain_sender  
Name user_sender  
Uint64 token_id  
Asset amount  
Checksum256 tx_id  
