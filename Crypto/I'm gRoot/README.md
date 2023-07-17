# I'm gRoot
>After decrypting the communication, you uncover the identity of the mole as the senior blockchain developer. Shockingly, the developer had embedded a backdoor in the government's decentralized blockchain network, originally designed to prevent corruption. You report this critical finding to the government council and are assigned with the task of detecting and fixing the backdoor, ensuring the integrity and security of the network.

## About the Challenge
We got a docker and a zip file (download here) that contains 2 python files. 

`server.py`
```python
from pymerkle import InmemoryTree as MerkleTree
from hashlib import sha256
from os import urandom

from secret import FLAG
from utils import *


class Transaction:

    def __init__(self, _from, _to):
        self._from = _from
        self._to = _to
        self._signature = self.getSignature(self._from, self._to)

    def signature(self):
        return self._signature

    def getSignature(self, _from, _to):
        return sha256(_from + _to).digest()


class Block:

    def __init__(self):
        self._transactions = []

    def transactions(self):
        return self._transactions

    def add(self, transaction):
        self._transactions.append(transaction)


class BlockChain:

    def __init__(self):
        self._mined_blocks = []

    def initialize(self):
        for _ in range(3):
            block = Block()
            for _ in range(8):
                transaction = Transaction(urandom(16), urandom(16))
                block.add(transaction)
            self.mine(block)

    def mined_blocks(self):
        return self._mined_blocks

    def size(self):
        return len(self._mined_blocks)

    def mine(self, block):
        self.mt = MerkleTree(security=False)
        for transaction in block.transactions():
            self.mt.append(transaction.signature())

        root_hash = self.mt.get_state()

        self._mined_blocks.append({
            "number": len(self._mined_blocks),
            "transactions": block.transactions(),
            "hash": root_hash.hex()
        })

    def valid(self, _signatures):
        _mt = MerkleTree(security=False)
        for _signature in _signatures:
            _mt.append(_signature)

        if self.mt.get_state() == _mt.get_state():
            return True

        return False


def main():
    blockchain = BlockChain()
    blockchain.initialize()
    mined_blocks = blockchain.mined_blocks()

    while True:
        menu()
        choice = input("> ")
        if choice == "1":
            print_mined_blocks(mined_blocks)
        elif choice == "2":
            # 1. Provide the forged signatures of the last block.
            _signatures = input("Forged transaction signatures: ")

            # 2. Test if the signatures are different from the provided ones.
            signatures = extract_signatures(mined_blocks[-1]["transactions"])
            _signatures = evaluate_signatures(_signatures, signatures)

            # 3. Test if the signatures you gave generate the same root hash.
            if blockchain.valid(_signatures):
                print(FLAG)
                exit(0)
            else:
                print("Try again")
        else:
            print("Good Bye")
            exit(0)


if __name__ == "__main__":
    main()
```

`util.py`
```python
def menu():
    print("[1] Explore mined blocks")
    print("[2] Forge the last block")


def extract_signatures(transactions):
    return [transaction.signature() for transaction in transactions]


def hexify(elements):
    return [element.hex() for element in elements]


def unhexify(elements):
    return [bytes.fromhex(element) for element in elements]


def print_mined_blocks(mined_blocks):
    for block in mined_blocks:
        print(f"Block: {block['number']}")
        print(f"Hash: {block['hash']}")
        print(
            f"Transactions: {hexify(extract_signatures(block['transactions']))}"
        )
        print()


def evaluate_signatures(_signatures, signatures):
    try:
        _signatures = _signatures.split(",")
        _signatures = unhexify(_signatures)
        if _signatures == signatures:
            print(f"Signatures are the same.")
            exit(0)
    except Exception as e:
        print(f"Something went wrong {e}")
        exit(0)

    return _signatures
```

## How to Solve?

Replace the 'IP',PORT with the IP and port you got after spawning the docker.
```python
from pwn import process, remote
from hashlib import sha256

def hash(a):
    return sha256(a).digest()
io = remote('IP',PORT)

io.sendlineafter(b"> ", b"1")
io.recvuntil(b"Block: 2")
io.recvuntil(b"Transactions: ")
m = [bytes.fromhex(x) for x in io.recvline().decode().strip("[']\n").split("', '")]
io.sendlineafter(b"> ", b"2")
ft = []
for i in range(0, len(m), 2):
    t = hash(m[i]) + hash(m[i + 1])
    ft.append(t)

io.sendlineafter(b": ", ",".join([x.hex() for x in ft]).encode())
print(io.recvline())
print(io.recvline())
io.close()
```
```
HTB{m32k13_72335_423_vu1n324813_8y_d3519n}
```
