
# Quantum-Resistant Messaging Protocol

## How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/itsAdee/QuantumMessaging
   cd QuantumMessaging
   ```

2. Install dependencies and activate the virtual environment:
   ```bash
   poetry install
   poetry shell
   ```

3. Start the client in **receive mode**:
   ```bash
   python client.py --role receive
   ```

4. Start the client in **send mode**:
   ```bash
   python client.py --role send
   ```

---

## Introduction

The **Quantum-Resistant Messaging Protocol** ensures secure communication by leveraging post-quantum cryptographic techniques to counter threats posed by quantum computing. It focuses on two key attributes:

- **Confidentiality**: Prevent unauthorized access using Kyber (lattice-based cryptography).
- **Integrity**: Ensure data remains unaltered using AES encryption.

---

## Features

1. **Post-Quantum Key Exchange (Kyber)**: Secure key exchange resistant to quantum attacks.
2. **Encryption and Integrity**: AES in EAX mode provides data encryption and tamper-proofing.
3. **Brute Force Resistance**: Large key space makes brute-forcing infeasible.
4. **Man-in-the-Middle (MITM) Resistance**: Key encapsulation secures communication.

---

## Implementation

### **Key Exchange**

- **Mechanism**: Uses Kyber to exchange public/private keys securely.
- **Purpose**: Derives a shared secret resistant to both classical and quantum attacks.

### **Encryption**

- **Algorithm**: AES in EAX mode for message encryption and integrity verification.
- **Key Derivation**: Uses HKDF to derive AES keys from the shared secret.

### **Message Flow**

1. **Client**:
   - Generates a key pair and sends the public key to the server.
   - Receives the encapsulated shared secret from the server.
   - Derives an AES key and uses it to encrypt and send messages.

2. **Server**:
   - Accepts the client's public key.
   - Encapsulates a shared secret and sends it back to the client.
   - Derives an AES key to decrypt and verify messages from the client.

---

## Attacks Simulated

1. **Brute Force**:
   - A reduced key space was used to simulate brute force attempts.
   - Results demonstrated the computational infeasibility of breaking keys under realistic conditions.

2. **Man-in-the-Middle (MITM)**:
   - Simulated interception of messages between the client and server.
   - Exploited the lack of digital signatures in key exchange, showcasing vulnerabilities.

---

## Results

- **Confidentiality**: Secured key exchange using Kyber.
- **Integrity**: Messages protected with AES encryption.
- **Attack Findings**:
  - Brute force attacks were computationally infeasible.
  - MITM attacks highlighted the need for additional defenses, such as digital signatures.

---

## Conclusion

This protocol demonstrates robust resistance to quantum and classical threats. It ensures secure communication by combining post-quantum cryptographic techniques with modern encryption algorithms. Future enhancements include implementing digital signatures for improved MITM resistance.

---

## References

- [Kyber: Post-Quantum Cryptography](https://pq-crystals.org/kyber/)
- [Signal Protocol Overview](https://signal.org/docs/)
- [Lattice-Based Cryptography Basics](https://medium.com/cryptoblog/what-is-lattice-based-cryptography-why-should-you-care-dbf9957ab717)
- [Forward and Backward Secrecy](https://signal.org/docs/specifications/doubleratchet/)
