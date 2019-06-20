# ChainWallet
This program is for hodlers who want to protect their bitcoins.

Imagine, somebody tortures you with the intention of getting your coins. In an extreme situation, you have no choice. The guy picks up your private key and immediately hands over the coins. What can you do to avoid this situation? Use the ChainWallet!

This wallet runs on a Unix or Linux terminal (compile with "make") and asks you for a few parameters in order to create a private key. It asks for a password and a exponential number that will define how many SHA256 rounds it will take to reach your private key. The number should be large. If you take a big base/exponent combination such as 2^40 or 10^12, the program will to run for many days until you get the wallet's public key.

sha256 (sha256 (sha256 (... sha256 (password) ...)))

The idea here is to have a wallet that takes a long time to be created. After generation, you should only keep the password, the base/exponent and the public key in a paper wallet. Do not keep the private key at first. All information will be saved to a file at the end of the program in Kryptonite format (https://github.com/Saulo-Fonseca/Kryptonite). Please edit this file to remove the private key.

If someone tries to get your key, you are not able to give it. Even if he gets some parameters from you, he has to run the program for many days until he finds out that you gave the wrong information. So, you have enough time to recover from the situation.

When the day arrives at which you want to stop hodling and transferring your coins to another location, you should re-generate your wallet with the same arguments. Then, after also waiting until the program concludes, you will get the private key back.
