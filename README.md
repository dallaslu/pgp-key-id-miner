# PGP Key ID Miner
Generate the PGP Key ID you want.

## Why?
Short IDs are insecure because they can be easily collided, so we need to use long IDs. But why not collide a convenient ID of your own to make long IDs just as easy to read and remember as they are to confirm?

`A3A7 1230 AABB CCDD` is easier to identify than `9710 B89B CA57 AD7C`. And there is no difference in security.

## Usage
### Complie
```bash
git clone https://github.com/dallaslu/pgp-key-id-miner
cd pgp-key-id-miner
mvn assembly:assembly
cd target
```
Or:

### Download
```bash
wget https://github.com/dallaslu/pgp-key-id-miner/releases/download/0.0.1/pgp-key-id-miner-0.0.1-jar-with-dependencies.jar
```

### Test
```bash
java -jar pgp-key-id-miner-0.0.1-jar-with-dependencies.jar
```
>Tue Feb 02 15:28:20 CST 2021 #0  
>Tue Feb 02 15:28:27 CST 2021 Got 46497FF457E16BE2A89C70193B2C65CC77000000 (Mon Feb 01 15:23:27 CST 2021), used 6s. #4237017  
>Tue Feb 02 15:28:27 CST 2021 Dumped with passphrase: UAwspD1EJKGOvnnboTmv

### Customization
`timeStartString`: `yyyy-MM-dd HH:mm:ss`; Optional, Reqired if `timeEndString` is specified  
`timeEndString`: `yyyy-MM-dd HH:mm:ss`; Optional  
`patterns`: Consists of 0123456789ABCDEF, `_` for arbitrary; Multiple, Optional

### Examples
```bash
java -jar pgp-key-id-miner-0.0.1-jar-with-dependencies.jar \
"2021-01-01 00:00:00" \
"2021-01-02 00:00:00" \
00000000 \
0000____0000 \
00000000________ \
DEADBEEF \
A_A_A_ \
>> pgp-key-id-miner.log &
```
```bash
java -jar pgp-key-id-miner-0.0.1-jar-with-dependencies.jar \
"2021-01-01 00:00:00" \
00000000 \
0000____0000 \
00000000________ \
DEADBEEF \
A_A_A_ \
>> pgp-key-id-miner.log &
```

### GnuPG
```bash
gpg --import 46497FF457E16BE2A89C70193B2C65CC77000000.sec
gpg --expert --edit-key 77000000
```
Next you should remove the default uid, add one of your own, and generate subkeys, at least one of which is used for encryption.
```bash
uid 1
deluid
adduid
addkey
save
```