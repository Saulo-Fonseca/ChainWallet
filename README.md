# ChainWallet
This program is designed for hodlers who want to protect their bitcoins.

Imagine someone threatening you to hand over your coins. In an extreme situation, you may have no choice but to comply. If the attacker obtains your private key, they can access your coins immediately. So, how can you prevent this scenario? By using the ChainWallet!

This wallet operates within a Unix or Linux terminal (compiled with "make") and prompts you for several parameters to create a private key. It requires a password and an exponential number, determining how many SHA256 rounds it will take to derive your private key. This number should be large. Opting for a significant base/exponent combination, such as 2^40 or 10^12, will result in the program running for many days until the wallet's public key is generated.

The concept here is to create a wallet that takes a substantial amount of time to generate. Upon completion, you should only retain the password, base/exponent values, and the public key, all stored in a paper wallet. Initially, refrain from keeping the private key. The program will save all information to a file in Kryptonite format (https://github.com/Saulo-Fonseca/Kryptonite). Please edit this file to remove the private key.

Even if someone attempts to obtain your key, you won't be able to provide it. Even if they manage to extract some parameters from you, they would need to run the program for an extended period before realizing any results, giving you ample time to react.

When the time comes to stop hodling and transfer your coins to another location, regenerate your wallet with the same arguments. After waiting for the program to complete once again, you'll retrieve the private key.

There is some discussion and even a challenge around ChainWallet. Here are some links you can visit:
* https://www.reddit.com/user/sauloqf/comments/a3q8dt/chainwallet/
* https://www.reddit.com/r/Bitcoin/comments/cya467/chainwallet_challenge_get_01_btc_if_you_solve_it/
* https://www.reddit.com/r/Bitcoin/comments/dinpw3/is_it_possible_to_directly_get_a_sha256_of_a/

There is also a JavaScript version of ChainWallet. Surprisingly, the version without a progress bar is even slightly faster than the C++ version. You can visit it here. The HTML files are available here in the JavaScript folder.
* https://www.astrotown.de/chainwallet/
