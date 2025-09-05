L'objectif de ce projet est de servir de ressource éducative et de référence pour comprendre les fondamentaux de la cryptographie et leur implémentation concrète en Java. Il couvre un large spectre de sujets, du chiffrement symétrique à la gestion des certificats X.509.
### 1. Chiffrement Symétrique
- **AES** (Advanced Encryption Standard) avec mode CBC et padding PKCS#5
- **Chiffrement basé sur mot de passe** (PBE) avec PBKDF2WithHmacSHA256
- **Chiffrement par flux** avec mode OFB (Output Feedback)

### 2. Intégrité et Authentification
- **HMAC** (Hash-based Message Authentication Code)
- **MGF1** (Mask Generation Function)
- **PKCS5 scheme** (pour la génération des clés)

### 3. Chiffrement Asymétrique et Signatures
- **Échange de clés avec RSA**
- **Protocole d'accord de clés Diffie-Hellman**
- **Signatures digitales** avec DSA

### 4. Certificats et PKI
- **Certificats X.509** (génération et manipulation)
- **Validation de chaîne de certificats**
- **OCSP** (Online Certificate Status Protocol)

### 5. Gestion des Clés et Certificats
- **KeyStore Java** (types JKS et PKCS12)
