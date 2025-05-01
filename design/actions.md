# ACTIONS

## lock  
- name user_domestic  
- name user_foreign  
- uint64_t token_id  
- asset quantity  

## claim  
- name user_domestic  
- name user_foreign  
- uint64_t token_id  
- asset quantity  
- checksum256 tx_id  

## addtoken  
- name token_contract_foreign  
- name token_contract_domestic  
- symbol token_symbol  
- name chain_foreign  
- name chain_domestic  

## togglelock  
- uint64_t token_id  
- bool freeze  

## toggleunlock  
- uint64_t token_id  
- bool freeze  

## setadmin  
- name new_admin  

## addchain  
- name chain_name  
- name bridge_contract  

## togglechain  
- name chain_name  
- bool enabled  

## freezeall  
- bool lock_frozen  
- bool unlock_frozen  

## ontransfer  
- name from  
- name to  
- asset quantity  
- string memo  