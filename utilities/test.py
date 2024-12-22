from utilities.ccakem import kem_keygen1024

priv, pub = kem_keygen1024()
print(len(priv))
print(len(pub))

