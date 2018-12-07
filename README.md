# ChainWallet
This program is for anyone who wants to protect their bitcoins.

Imagine, somebody tortures you with the intention of getting your coins. In an extreme situation, you have no choice. The guy picks up your private key and immediately hands over the coins. What can you do to avoid this situation? Use the ChainWallet!

This wallet runs on a Linux terminal (compile with "make") and asks you for a few parameters in order to create a private key. You will then be also asked how many SHA256 rounds it will take to reach your private key in the form of a base and exponent. The number should be large. If you take a big base/exponent such as 2^40 or 10^12, the program will to run many days until you get the wallet's private and public key.

sha256 (sha256 (sha256 (... sha256 (password) ...)))

The idea here is to have a wallet that takes a long time to be created. After generation, you only keep the password, the base/exponent and the public key. Do not store the private key at first.

If someone tries to get it from you, he has to run the program for many days until he finds out that you gave the wrong password or exponent. So you have enough time to recover from the situation.

When the day arrives at which you want to stop hodling and transferring your coins to another location, you should re-generate your wallet with the same arguments. Then, after also waiting until the program concludes, you will get the private key back.