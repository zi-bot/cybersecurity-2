# Evidence sheet — Track 1 (Symmetric)

Name / Student ID: Nur Agni Try Anindhiya / S1324004  Date: 28/10/2026

One row per step. Keep each cell short and checkable, paste real output, and **never write a key value** — write how you obtained it.

| Case | Vulnerable code (file/line) | Your payload / test step | Output evidence | Fix | Re-test result |
|---|---|---|---|---|---|
| C1–C2 Caesar (warm-up, not graded) | `c1_caesar.py` |ran brute_force on caesar_message.txt |shift  7: ORDER-0000042 HAS BEEN SHIPPED TO THE BEKASI WAREHOUSE. This Caesar cipher is Ngit add 1_symmetric/starter/c1_caesar.py 1_symmetric/evidence_sheet.mdOT secure for any secret. |Use AES-GCM instead (S1) | Not Applicable, It is a toy chhiper. |
| S1–S2 AES-GCM done right | — |python 1_symmetric/starter/s1_vault_gcm.py| S1 round-trip: True, S2 tampered ciphertext rejected: InvalidTag |Use standard AES-GCM with 96-bit random nonce (os.urandom(12)) and auth tag verification |Verified Pass (Ciphertext decrypted and integrity verified successfully) |
| S3 ECB leaks patterns | `weak_ecb.py` | | | | |
| S4 ECB without authentication | `weak_ecb.py` | | | | |
| S5 Reused nonce | `weak_fixed_nonce.py` | | | | |
| S6 Embedded key | `weak_embedded_key.py` | | | | |

## Short explanation (2–3 sentences each)

- Why are ECB and a fixed nonce dangerous?
- Why does an embedded key make encryption useless?

_____________________________________________________________________
