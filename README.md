This program seals away a message which will take some configurable duration
to open.

Usage:
```
./timelock seal <duration> <message> <outfile>
./timelock open <sealed_file>
<duration> is expressed in seconds.
```


Example:

```
$ time ./timelock seal 20 "hello world" hello.sealed
Measuring decryption speed for 10 seconds...
This computer can do about 33277 decryptions per seconds of 1 blocks of 16 bytes.
So we will encrypt 665540 times to make it last 20 seconds to decrypt.

real    0m12.563s
user    0m12.537s
sys     0m0.000s

$ time ./timelock open hello.sealed
Iteration count = 665540
Message length = 11
Originally requested duration = 20 seconds
Message:
hello world

real    0m20.324s
user    0m20.321s
sys     0m0.001s
```
