# fspke/examples
Simple CLI tool examples utilizing CHK forward secure PKE

# Tutorial

## Creating Keys

1. Create a Private Key

    As usual, Alice wants to send a message to Bob. In order to do so, Bob must
    create a private key and then derive a public key (which he provides Alice). 

    ```
    python3 chk-gen.py > bob.privkey
    python3 chk-pub.py --file bob.privkey > bob.pubkey
    cat bob.privkey
    cat bob.pubkey
    ```
    
    You'll notice that the private key is significantly larger than the public
    key. The default configuration will allow >16 million intervals (and
    contains up to 91 keys to enable derivation of the individual interval
    keys)

## Sending a message

1. Encode a message

    ```
    echo "Hello, Bob!" | python3 chk-enc.py --interval=10 bob.pubkey > ctext10
    ```

1. Decode the message

    ```
    cat ctext10 | python3 chk-dec.py --interval=10 bob.privkey
    ```

## Implementing forward security

1. Derive a private key for an interval (the future)

    ```
    cat bob.privkey | python3 chk-der.py --interval=20 > bob20.privkey
    ```

1. Encode a message for the future

    ```
    echo "Bye, Bob!" | python3 chk-enc.py --interval=30 bob.pubkey > ctext30
    ```

1. Verify that private keys can only decode for newer (greater) intervals

    ```
    cat ctext10 | python3 chk-dec.py --interval=10 bob.privkey
    cat ctext10 | python3 chk-dec.py --interval=10 bob20.privkey
    cat ctext30 | python3 chk-dec.py --interval=30 bob.privkey
    cat ctext30 | python3 chk-dec.py --interval=30 bob20.privkey
    ```

    From this example, note that the original (interval 0) private key can
    decrypt both messages, but the newer (interval 20) private key can only
    decrypt messages from the future (ctext30), whereas messages from the past
    (ctext) are forward secure. So, presuming the older private key material is
    truly deleted, even if your private key is compromised older messages
    cannot be decrypted.

For more information on the algorithm and associated security proof, please
refer to ["A Forward-Secure Public Key Encryption Scheme"; Ran Canetti, Shai Halevi and Jonathan Katz](https://eprint.iacr.org/2003/083.pdf)
