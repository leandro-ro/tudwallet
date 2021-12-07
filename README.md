# tudwallet
This project is a deterministic ethereum wallet that utilizes cryptographic operations from an underlying Java implementation by @CROSSINGTUD, which is based on "A Formal Treatment of Deterministic Wallets" by Das et al. CCS'19 - https://dl.acm.org/doi/abs/10.1145/3319535.3354236

The underlying cryptography provides the wallet with a randomized ECDSA scheme to generate ECDSA key pairs in a hot/cold wallet environment. The main key pair allows deriving other key pairs intended to be used as (one-time) ethereum accounts. Notably, this wallet makes the provided java implementation of the hot and cold wallet accessible in a python environment, adds proper state management and a synchronization mechanism that only accesses the cold wallet when needed.

## Requirements
### General
- python3 - e.g. on Ubuntu via `sudo apt install python3.8`
- java - e.g. on Ubuntu via `sudo apt install default-jre`

### Python libraries
- eth_accounts - `pip3 install eth_account`
- eth_utils - `pip3 install eth_utils`
- jpype - `pip3 install jpype1`

## Usage Examples and Explanation
### Running Unit Tests
When running the unit tests, make sure the working directory points at the main directory and not the test directory. From the main directory, you can simply use
`python3 -m unittest discover -s tests -t ../tudwallet
`
to run all test cases.

### Wallet initialization
To initialize the wallet, import the `wallet` module and create a wallet object. `base_directory_hw` sets the storage location for all data concerning the hot wallet and `base_directory_cw` for all data concerning the cold wallet. Please keep in mind that in production scenarios, the cold wallet location is intended only to come online when needed.
```python
import wallet as tud
test_wallet = tud.Wallet(base_directory_hw="Documents/HotWallet/", base_directory_cw="OtherDrive/ColdWallet/")
test_wallet.generate_master_key(overwrite=False)
```
`.generate_master_key()` creates a new master key pair. The overwrite argument is by default set to `False` - if set to `True`, a potentially existing key pair is being replaced with a new one. Note that if overwrite is set to `False` and there is already a master key pair existing (under the given paths in `base_directory_hw`, `base_directory_cw`) an exception is raised. Therefore, `.generate_master_key()` is only to be called if no key pair exists or an existing key pair should be replaced.
### Key derivation
The public and the secret part of each key pair are derived separately, and it is advised to derive the secret part only when needed to keep the interaction with the cold wallet low. Keys can be derived (and are later identified, e.g., for signing) with a unique ID. 

If no ID is given for `.public_key_derive()`, the resulting public key ID will be the last used ID incremented by 1. If an ID is given, **it is required to be higher than all previously used IDs**. Otherwise, an exception will be raised.

If no ID is given for `.secret_key_derive()` the ID associated with the last derived public key is used. If an ID is given, the associated public key must have been derived earlier, otherwise an exception will be raised.
```python
test_wallet.public_key_derive()  # id=1
test_wallet.public_key_derive()  # id=2
test_wallet.public_key_derive(id=5) # id=5

test_wallet.get_all_ids()  # results in [1, 2, 5]

test_wallet.secret_key_derive(id=1)  # Secret key for public key with id=1
test_wallet.secret_key_derive()  # Secret key for the latest derived public key, therefore id=5
```

### Message signing
To sign a message use `.sign_message()`. The ID specifies which (already derived!) key pair is being used for signing. An exception will be raised if an ID is given that was not used to derive a public and secret key earlier.
```python
message = "This is a test!"
signed_msg = test_wallet.sign_message(message=message, id=1)
```
The signed message contains the `messageHash`, the full `signature`, and the raw signature as `r`, `s`, `v`.

### Transaction signing
To sign a transaction use `.sign_transaction()`. The ID specifies which (already derived!) key pair is being used for signing. If an ID is given that was not used to derive a public and secret key earlier, an exception will be raised.
```python
transaction = {
    # Note that the address must be in checksum format or native bytes:
    'to': '0x82fc853256B05029b3759161B32E3460Fe4eaC77',
    'value': 10000000000000000,
    'gas': 2000000,
    'gasPrice': 2500000008,
    'nonce': 1, 
    'chainId': 3,  # Ropsten Testnet ID = 3
}

signed_tx = test_wallet.sign_transaction(transaction_dict=transaction, id=1)
```
The signed transaction contains the `rawTransaction`, which can be used to publish the transaction to the ethereum network, the transaction `hash`, and the raw signature as `r`, `s`, `v`.
