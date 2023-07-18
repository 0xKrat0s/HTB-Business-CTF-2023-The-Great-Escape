# Paid Contr-actor (Blockchain Challenge)
HTB Business CTF 2023
Writeup by: @godylockz

## Challenge Description
Category: Blockchain
Difficulty: Very Easy
Points: 650
After a lifetime of preparation, the moment has arrived to enlist in the esteemed military of the United Nations of Zenium as an expert in blockchain security. Before embarking on your duties, there is a small matter of paperwork that requires your attention.

## Challenge Files
Contract.sol
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.18;

contract Contract {
    bool public signed;

    function signContract(uint256 signature) external {
        if (signature == 1337) {
            signed = true;
        }
    }
}
```
Setup.sol
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.18;

import {Contract} from "./Contract.sol";

contract Setup {
    Contract public immutable TARGET;

    constructor() {
        TARGET = new Contract();
    }

    function isSolved() public view returns (bool) {
        return TARGET.signed();
    }
}
```
README.md
```text
## Guidelines

The point of this README is to provide some guidance for people who attempt solving a blockchain challenge for the first time.

### Ports

As you have already seen, there are 2 ports provided.

- The one port is the `tcp` port, which is used to retrieve information about connecting to the private chain, such as private key, and the target contract's addresses. You can connect to this one using `netcat`.
- The other port is the `rpc` url. You will need this in order to connect to the private chain.

In order to figure out which one is which, try using `netcat` against both. The one which works is the `tcp` port, while the other one is the `rpc url`.

### Contract Sources

In these challenges, you will meet 2 type of smart contract source files, the `Setup.sol` file and the challenge files.

#### Setup.sol

The `Setup.sol` file contains a single contract, the `Setup`. As the name indicates, inside this contract all the initialization actions are happening. There will typically be 3 functions:

- `constructor()`: It is called automatically once when the contract is deployed and cannot be called again. It contains all the initialization actions of the challenge, like deploying the challenge contracts and any other actions needed.
- `TARGET()`: It returns the address of the challenge contract.
- `isSolved()`: This function contains the final objective of the challenge. It returns `true` if the challenge is solved, `false` otherwise. By reading its source, one is able to figure out what the objective is.

#### Other source files

All the other files provided are the challenge contracts. You will only have to interact with them to solve the challenge. Try analyzing their source carefully and figure out how to break them, following the objective specified in `isSolved` function of the `Setup` contract.

### Interacting with the blockchain

In order to interact wth the smart contracts in the private chain, you will need:

- A private key with some ether. We provide it via the tcp endpoint.
- The target contract's address. We provide both the Setup's and the Target's addresses.
- The rpc url, which can be found using what described earlier.

After having collected all the connection information, then you can either use `web3py` or `web3js` to perform function calls in the smart contracts or any other actions needed. You can find some useful tutorials about both with a little googlin'.
An even handier way is using a tool like `foundry-rs`, which is an easy-to-use cli utility to interact with the blockchain, but there are less examples online than the other alternatives.
```

## Strategy
The code below leverages the Web3 Python3 package to communicate with the blockchain and facilitate the exchange of smart contracts. The `Setup.sol` contract is a crucial component and contains a `signContract()` function. When this function is invoked with the value `1337`, it will lead to the successful completion of the challenge.

## Python Solution Code
```python
# Imports
from web3 import Web3
from solcx import compile_files, compile_source
from pwn import *

# Connection settings
provider_address = "http://94.237.54.201:31093"
url = '94.237.54.201'
port = 34068


def launch_instance():
    info('Launch instance...')
    r = remote(url, port)
    r.sendlineafter(b'action? ', b'1')
    r.recvuntil(b'Private key     :  ')
    private_key = r.recvline().strip().decode()
    r.recvuntil(b'Address         :  ')
    player_wallet_address = r.recvline().strip().decode()
    r.recvuntil(b'Target contract :  ')
    target_contact = r.recvline().strip().decode()
    r.recvuntil(b'Setup contract  :  ')
    setup_contract_address = r.recvline().strip().decode()
    r.close()
    info(f'private_key                    : {private_key}')
    info(f'wallet_address                 : {player_wallet_address}')
    info(f'target_contract_address        : {target_contract_address}')
    info(f'setup_contract_address         : {setup_contract_address}')
    return private_key, player_wallet_address, target_contact, setup_contract_address


def kill_instance():
    info('Kill instance...')
    r = remote(url, port)
    r.sendlineafter(b'action? ', b'2')
    r.close()


def get_flag():
    info('Get Flag...')
    r = remote(url, port)
    r.sendlineafter(b'action? ', b'3')
    flag = r.readrepeat(1)
    r.close()
    return flag


# Launch instance
private_key = ''
player_wallet_address = ''
target_contract_address = ''
setup_contract_address = ''
if private_key == '':
    private_key, player_wallet_address, target_contract_address, setup_contract_address = launch_instance()

# Connect to the network
w3 = Web3(Web3.HTTPProvider(provider_address))
assert w3.is_connected()

# Load the private key
player = w3.eth.account.from_key(private_key)
player_wallet_address = player.address
player_balance = w3.eth.get_balance(player_wallet_address)
info(f'Player Address                 : {player_wallet_address}')
info(f'Player Balance                 : {player_balance} wei')

# Compile the contracts from files
current_dir = os.path.dirname(os.path.abspath(__file__))
target_contract_filename = os.path.join(current_dir, "Contract.sol")
setup_contract_filename = os.path.join(current_dir, "Setup.sol")
compiled_contracts = compile_files(
    [target_contract_filename, setup_contract_filename], solc_version="0.8.18", output_values=["bin", "abi"])

# Get the contract interfaces
keys = compiled_contracts.keys()
target_contract_interface = compiled_contracts[next((key for key in keys if key.endswith(":Contract")), None)]
setup_contract_interface = compiled_contracts[next((key for key in keys if key.endswith(":Setup")), None)]

# Create a contract instance for the deployed contracts
setup_contract_instance = w3.eth.contract(
    address=setup_contract_address, abi=setup_contract_interface['abi'], bytecode=setup_contract_interface['bin'])
target_contract_instance = w3.eth.contract(
    address=target_contract_address, abi=target_contract_interface['abi'], bytecode=target_contract_interface['bin'])

# Submit the transaction to call `signContract()` function
call_function = target_contract_instance.functions.signContract(1337).build_transaction(
    {"chainId": w3.eth.chain_id, "nonce": w3.eth.get_transaction_count(player_wallet_address), "from": player_wallet_address})
signed_tx = w3.eth.account.sign_transaction(
    call_function, private_key=private_key)
send_tx = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(send_tx)

# Call the `isSolved()` function to retrieve the value of the flag
assert setup_contract_instance.functions.isSolved().call()

out = get_flag()
success(out.decode())
```

```sh
$ python3 paidcontractor.py
[*] Launch instance...
[+] Opening connection to 94.237.54.201 on port 34068: Done
[*] Closed connection to 94.237.54.201 port 34068
[*] private_key                    : 0x61e8e469fd4bf0bccbf5b50b0d66b63cdacdd0f8678afc24439b788b52eb8905
[*] wallet_address                 : 0xF8203a31a1486f193A410564A5071544336dC464
[*] target_contract_address        : 
[*] setup_contract_address         : 0xD0aaE5659B86C9565dBBef92Fef6c94508d85438
[*] Player Address                 : 0xF8203a31a1486f193A410564A5071544336dC464
[*] Player Balance                 : 5000000000000000000000 wei
[*] Get Flag...
[+] Opening connection to 94.237.54.201 on port 34068: Done
[*] Closed connection to 94.237.54.201 port 34068
[+] HTB{c0n9247u14710n5_y0u_423_kn0w_p427_0f_7h3_734m}
```

Flag: `HTB{c0n9247u14710n5_y0u_423_kn0w_p427_0f_7h3_734m}`

## Foundry-RS Solution
Another method to solve this challenge is to use [Foundry-RS](https://github.com/foundry-rs/foundry). Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust. 

Send transaction via Foundry-RS(cast)
```sh
$ cast send --rpc-url=<RPC_URL> --private-key=<PRIVATE_KEY> <ENTRANT_CONTRACT_ADDRESS> "<FUNCTION_SIGNATURE>" <ARGUMENTS>
```

```
$ cast send --rpc-url=http://83.136.254.139:52787 --private-key 0x1fb7cfdee6cd2f91aca81e01c6f9577b4d8de776ced6522ba13aa1d7c731f7a0 0x5C1b12a6ee46dDC56A3A6C55dC6fd9eBf0bE97Ef "signContract(uint256)" 1337

blockHash               0x8b7f905c8a1611defc613eb9317b0925ee82399c7bf3ff779db34b43b394649f
blockNumber             2
contractAddress         
cumulativeGasUsed       43586
effectiveGasPrice       3000000000
gasUsed                 43586
logs                    []
logsBloom               0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
root                    
status                  1
transactionHash         0x85ec9a8353a84aeb220eae81bdacd70bb8ed9633f558387230a31554567814a6
transactionIndex        0
type                    2
```

```sh
$ nc 83.136.254.139 42228
1 - Connection information
2 - Restart Instance
3 - Get flag
action? 3
HTB{c0n9247u14710n5_y0u_423_kn0w_p427_0f_7h3_734m}
```

Flag: `HTB{c0n9247u14710n5_y0u_423_kn0w_p427_0f_7h3_734m}`