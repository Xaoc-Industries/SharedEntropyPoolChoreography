# HekateForge SEPC Protocol (Patent Pending)

**SEPC** (Shared Entropy Pool Choreography) is a novel cryptographic system for secure, deniable, and forensically resistant communication. Unlike conventional encryption, **no ciphertext is ever transmitted**. Instead, messages are encoded into index references within a shared entropy pool, enabling zero-payload quantum-resilient messaging.

> **Patent Pending — CA #3278624**  
> **Author**: William Appleton  
> **License**: Non-commercial demo use only (see [LICENSE])

---

## 🚀 Key Features

- 🔒 No ciphertext in transit — payloads are reconstructed from entropy pool references  
- 🔐 XOR-based segment chaining with evolving keys derived from a shared license artifact  
- ⏱️ Ephemeral entropy pools with TTL-based expiry (default: 5 minutes)  
- 🧩 JSON-based entropy pools containing all base64 characters  
- 📦 Zlib compression of final payload descriptor (`PLD`)  
- 🧪 CLI-based encoder/decoder for PoC and research testing  

---

## 📁 Project Structure

```bash
SEPC/
├── sepc.py              # Main encoder/decoder tool
├── sepc-vault.py        # Entropy pool vault API
├── LICENSE              # Licensing terms (non-commercial only)
├── README.md            # This file
├── binaries/
│   └── sepc             # Encoder/decoder tool Linux binary
│   └── sepc.exe         # Encoder/decoder tool Windows executable
├── docs/
│   └── Shared Entropy Pool Choreography Version 1_1.pdf  # SEPC Version 1.1 Whitepaper
├── examples/
│   ├── CypferCoKey.PLD
│   └── entropy_pool_example.json
```

---

## 🛠️ How It Works

1. Convert your plaintext to Base64.
2. Map each Base64 byte to index positions within a shared entropy pool.
3. Encode those indexes into a variable-length string.
4. Chunk the string and XOR each segment:
   - Key1 = `sum(LIC bytes) * SEED`
   - Subsequent keys = `sum(previous segment bytes) * (n * segment length)`
5. Compress the XORed data into a `PLD`.
6. The receiver uses the same entropy pool + LIC + seed to reverse the process and decrypt the message.

---

## ⚙️ Usage

### 🔐 Encrypt a secret file:
```bash
python3 SEPC.py \
  -s examples/sample_secret.txt \
  -p http://hekateforge.com:8080/pool \
  -l my_license_value \
  -sl 6 \
  -sv 42 \
  -o output.pld
```

### 🔓 Decrypt a PLD file:
```bash
python3 SEPC.py \
  -d output.pld \
  -p http://hekateforge.com:8080/pool/{PoolIDHash} \
  -l my_license_value \
  -sl 6 \
  -sv 42 \
  -o secret_recovered.txt
```

---

## 📦 Entropy Pool Format (JSON)

Example:
```json
{
    "PoolID": "0",
    "TTL": 1752213416,
    "GeneratedAt": 1752212816,
    "EnSrc": "V1.1",
    "SHA256": "21eb60c...",
    "Data": "/QiQ6N}eWGb}Em;,BH_u6?vv=c'08%c/rQh'yK746'w.AiWqp%Y`hjoK'`bO..."
}
```

- `Data` must include all base64 characters
- Must be accessible by both sender and receiver during TTL window

---

## 🧠 Applications

- Secure government or military messaging  
- Medical device communication  
- SCADA and ICS environments  
- Post-quantum secure chat frameworks

---

## ⚠️ Disclaimer

This software is provided **for demonstration and non-commercial use only**. Commercial use requires prior written permission from the author. Patent pending: CA #3278624. See [LICENSE]

---

## 📬 Contact

For licensing, usage inquiries, or integration support:

**William Appleton**  
📧 william@xaocindustries.com
