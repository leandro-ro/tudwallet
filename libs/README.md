## Note: Signing functionality of the java implementation
Although the underlying (in java implemented) cryptography provides a custom ECDSA signing algorithm, we use the signing functionality supplied by the eth_account library. 
The custom singing algorithm is currently not compatible with the ECDSA signing standard [RFC6979](https://datatracker.ietf.org/doc/html/rfc6979) used by ethereum because it is probabilistic. 
A change in the java implementation is required that adapts the signing algorithm to the (deterministic) RFC6979 standard. 
Our wallet codebase already accommodates using the java implementation's signing algorithm in the "experimental_signing" branch.
