# tudwallet
This project is an deterministic ethereum wallet that utilizes cryptographic operations from an underlying Java implementation by @CROSSINGTUD which is based on "A Formal Treatment of Deterministic Wallets" by Das et al. CCS'19 - https://dl.acm.org/doi/abs/10.1145/3319535.3354236

The underlying cryptography provides the wallet with an randomized ECDSA scheme to generate ECDSA key pairs in an hot/cold wallet setting. The main key pair allows to derive further key pairs that are intented to be used as (one time) ethereum accounts. Notably this wallet makes the provided java implementation of the hot and cold wallet accessible in a python environment, adds proper state management and a synchronization mechanism that only accesses the cold wallet when needed.

## Usage Examples and Explanation
### Running Unit Tests
When running the unit tests make sure the working directory is pointing at the whole directory and not the test folder. E.g.
```shellscript
python3 -m unittest discover -s /Users/lr/Documents/Repos/tudwallet/tests -t /Users/lr/Documents/Repos/tudwallet
```

### Wallet initialization
To initialize the wallet import the `wallet` module and create a wallet object. `base_directory_hw` sets the storage location for all data concerning the hot wallet and `base_directory_cw` for all data concerning the cold wallet. Please keep in mind that in real usage scenarios the cold wallet location in intended to be able to come online / go offline when needed.
```python
import wallet as tud

test_wallet = tud.Wallet(base_directory_hw="/Documents/HotWallet/", base_directory_cw="/OtherDrive/ColdWallet/")
test_wallet.generate_master_key()
```
