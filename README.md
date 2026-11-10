# immutable-edge-measurements

Measurements behind the dual-signature boot verification discussed in
*The Immutable Edge: Selecting Hardware Trust for Long-Lifecycle Industrial
IoT Devices*.

The idea in the paper: the boot ROM can only check RSA or ECDSA, and that
cannot change for the life of the chip. The boot loader it verifies can
carry a second verifier, and that verifier accepts the next image only if
both a classical signature and a post-quantum signature check out. This
repository measures what that second check costs.

## What is here

| File | Purpose |
|---|---|
| `measure_verify.py` | Generates keys, signs the SHA-256 digest of a 1 MiB test image, and times verification for RSA-3072, ECDSA P-256 and ML-DSA-44/65/87. Also checks that the acceptance rule rejects an image when either signature or the image itself is altered. |
| `lms.py` | A small LMS (RFC 8554) implementation, H10/W4, used for signature and key sizes and for counting the hash work in a verification. Not for production use. |
| `summarize.py` | Takes the median of each figure over the files in `runs/` and prints the table used in the paper. |
| `runs/` | Raw output of the five runs reported in the paper. |
| `results.txt` | Output of `summarize.py` for those runs. |

## Running it

```
pip install -r requirements.txt
for i in 1 2 3 4 5; do python3 measure_verify.py > runs/run$i.json; done
python3 summarize.py
```

The figures in the paper were taken on a 2.1 GHz Intel Xeon (x64) with
OpenSSL 4.0.2 through the Python `cryptography` package. Times on an
embedded processor will be different, and the point of the numbers is the
relative cost: the second signature against the RSA check and against
hashing the image.

## Notes

- Signatures are made over the SHA-256 digest of the image, which is how
  most boot loaders verify.
- LMS verification time is not reported. The script records the number of
  SHA-256 blocks a verification uses (around 560), which can be turned into
  a time on a given processor.
- Each LMS key in this parameter set can sign 1024 images, and the signer
  has to keep track of which one-time keys have been used.

## License

MIT
