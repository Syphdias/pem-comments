**This is currently work in progress, please check back in a few days or weeks,
when I am happy with the result.**

## Disclaimer

I am not an expert on crypotgraphy (neither topic nor library) and do this in a
best-effort manor. Do not rely on this to properly verify certificates, keys or
otherwise. It is based on a few assumptions that might not fit your case.

The purpose is to give a quick human readable comment for each pem.
This might also be useful in a yaml file.

## Origin

While handling certificates and private keys, I often find myself in need of
verifying a key belongs to a certificate or that the provided intermediate
certificate is indeed the one that issued the main certificate.

## Ideas/Wishes

- Add unit tests with certificates, etc.
  - every type
  - dublicates, so id can be checked
  - for command line option
- Add list of programs (with versions) that support pem comments pipeline?
- pipline to make me check requirements
- (TODOs in script itself)
