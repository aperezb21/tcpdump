```
# Installation Notes for tcpdump with cryptopANT

## Required Tools

Make sure you have the following tools installed:

```bash
sudo apt-get install build-essential
sudo apt-get install libssl-dev
sudo apt-get install autoconf
sudo apt-get install git libpcap-dev
```

## Download and Install cryptopANT

1. **Download cryptopANT 1.3.0:**

   You can download it from [cryptopANT official site](https://ant.isi.edu/software/cryptopANT/index.html).

2. **Extract and Install cryptopANT:**

   ```bash
   tar -xzvf cryptopANT-1.3.0.tar.gz
   cd cryptopANT-1.3.0
   ./configure --with-scramble_ips=yes
   make
   sudo make install
   ```

3. **Reload Libraries:**

   ```bash
   sudo ldconfig
   ```

## Compile tcpdump with Anonymization Support

1. **Clone the tcpdump Repository:**

   ```bash
   git clone https://github.com/aperezb21/tcpdump
   cd tcpdump
   ```

2. **Prepare for Compilation:**

   ```bash
   ./autogen.sh
   ./configure --with-cryptopant=yes
   ```

3. **Compile tcpdump:**

   ```bash
   make
   ```

4. **Run Tests (optional):**

   ```bash
   make check
   ```

## Using tcpdump with Anonymization

Once compiled, you can use tcpdump with anonymization options:

```bash
./tcpdump --anon path_keyfile ...
```

### Anonymization Options for tcpdump

- `--anon [key]`: Captured packets will be anonymized with `[key]`. `[key]` can be a path to a key created with `scramble_ips --newkey`. If `[key]` does not exist, it will be created.
- `--danon [key]`: Captured packets will be deanonymized with `[key]`. `[key]` can be a path to a key created with `scramble_ips --newkey`. If `[key]` does not exist, it will be created.
- `--pass4 [bits]`: The first `[bits]` in IPv4 addresses will not be altered in the anonymization (use in combination with `--anon` or `--danon`).
- `--pass6 [bits]`: The first `[bits]` in IPv6 addresses will not be altered in the anonymization (use in combination with `--anon` or `--danon`).
- `--c4 [aes|md5|sha1|blowfish]`: Choose cipher for IPv4 anonymization. The key will be created according to the cipher mode, meaning the key is cipher-dependent.
- `--c6 [aes|md5|sha1|blowfish]`: Choose cipher for IPv6 anonymization. The key will be created according to the cipher mode, meaning the key is cipher-dependent.

### cryptopANT Commands

- **Create a Key:**

  ```bash
  scramble_ips --newkey newkeyfile.cryptopant
  ```

Feel free to reach out if you have any questions or run into issues!
```