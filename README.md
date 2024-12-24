
# Quantum-Resistant Messaging Protocol
## How to Run
   ```bash
   git clone itsAdee/QuantumMessaging
   cd QUANTUMMESAAGING
   run poetry install
   run poetry shell
   run python client.py --role receive
   run python client.py --role send

## Introduction

The **Quantum-Resistant Messaging Protocol** ensures secure communication by leveraging post-quantum cryptographic techniques to counter threats posed by quantum computing. It focuses on two key attributes:

- **Confidentiality**: Prevent unauthorized access using Kyber (lattice-based cryptography).
- **Integrity**: Ensure data remains unaltered using AES encryption.

## Features

1. **Post-Quantum Key Exchange (Kyber)**: Secure key exchange resistant to quantum attacks.
2. **Encryption and Integrity**: AES in EAX mode provides data encryption and tamper-proofing.
3. **Brute Force Resistance**: Large key space makes brute-forcing infeasible.
4. **Man-in-the-Middle (MITM) Resistance**: Key encapsulation secures communication.

## Implementation

- **Key Exchange**: Public/private keys exchanged using Kyber.
- **Encryption**: AES with keys derived via HKDF from shared secrets.
- **Flow**:
  1. Client sends public key; server responds with encapsulated shared secret.
  2. Shared secret is used to encrypt and verify messages.

## Attacks Simulated

1. **Brute Force**:
   - Tested reduced key spaces to demonstrate computational infeasibility.
2. **MITM**:
   - Intercepted messages by impersonating both sides, showcasing the need for digital signatures.

## Results

- **Confidentiality**: Secured key exchange using Kyber.
- **Integrity**: Messages protected with AES encryption.
- **Attack Findings**: Brute force is computationally infeasible; MITM requires additional defenses.

## Conclusion

This protocol demonstrates strong resistance to quantum and classical threats while highlighting areas for enhancement, such as implementing digital signatures.

## References

- [Kyber: Post-Quantum Cryptography](https://pq-crystals.org/kyber/)
- [Lattice-Based Cryptography Basics](https://medium.com/cryptoblog/what-is-lattice-based-cryptography-why-should-you-care-dbf9957ab717)
