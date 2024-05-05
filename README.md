# keygen

Creates keys and passwords. Most likely better than some other product.

* Made with Rust.
* Works on modern Intel & AMD CPUs.
* Multiple sets of alphabet and wordlists, easily expandable.
* Proper random number generation.
* Supports randomness testing.


## Usage

### Parameters

```
keygen.exe --help
Keygen 0.0.4
Generates random passwords and keys.

USAGE:
    keygen.exe [FLAGS] [OPTIONS]

FLAGS:
        --debug      Enable debug mode
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -a, --alphabet <ALPHABET>             Specify the alphabet to use for random value generation [possible values:
                                          words-fi, commonsafe, normal, ascii, assembly]
    -b, --bits <BITS>                     Specify the amount of bits for each random value
    -c, --count <COUNT>                   Number of passwords to generate
    -d, --delimiter <DELIMITER>           Sets the delimiter between each letter or word
    -f, --format <format>                 Specifies the data format for RNG testing. [possible values: raw, u8, u16,
                                          u32, u64]
    -r, --rngtest <generator>             Optional test mode for RNG testing. Will provide raw bytes to stdout.
                                          [possible values: rdrand, os, cpujitter, cpujitter-raw]
    -s, --size <data size (u64 words)>    Specifies the generated data size in u64 words for RNG testing.
```

### Examples
```
keygen
6fqCU.%2rRxeiHModx4GX62pJdej227kpm,A,fgX4hh2

keygen --alphabet commonsafe --bits 128 --count 3
!1onVJeL7UPLr6wxsTofGJ
oj32b7MQbfkGdGoqpfMSNS
cTvKp%geNAV45i4jwdp,n1

keygen --alphabet words-fi --bits 128 --count 3 --delimiter .
santsari.hoilotus.sanomus.salkuton.tahko.toga.kaidepuu.vehtaus.drinksu
iilimato.monismi.kitara.ivailu.muovauma.suoritin.periksi.tiptop.vuorata
virtsata.mailata.sakaali.lakaista.verkkaan.jin.valtuus.rampuus.jaettava

keygen -a assembly -b 64 -c 3 --delimiter .
snobi.panda.mättö.kantapää.vihreä.kuusi.harmaa.töppönen.kynttilä
kynttilä.pleksi.mankeli.itiö.pora.kruiseri.peukalo.basso.elämä
kirppis.limusiini.suklaa.villi.höyry.lusikka.töppönen.sima.hieno

keygen -a ascii -b 196 -c 3
e7&pD(LVbFwW&2Q9=[F*SE?R0?mg?9
2),L7>]#jF+H1J^s~5q@^6U<+ICl[=
j|!XK`44'EAU'MwCv7-<,Ydb#@T@:a

keygen -a ascii -b 256 -c 3
'.l7yk=,L>+w@I\2B-G~IA6t}!>FOO:ABN3y s|
5bcH!{jQN|nu}0mnh[j$u_|BJIQ:Bm{c`+Y/c}9
e<m2szElOINahV0`N(j@O).%30QGLQxC#Eag(;=
```

## Building
### In Linux
```
$ git clone https://github.com/TuningSweeper/keygen.git
$ cd keygen/src
keygen/src$ cargo build --release
```
Will result in binary file in target/release/keygen

## Binary files?

I have some pre-build binaries available for Linux and Windows. Check https://github.com/TuningSweeper/keygen/binaries
Before using these for anything real, check with me *personally* how to verify the integrity of these.

## Custom builds or features? 
Sure, ask me. I can do for example:

* dedicated builds using disconnected hosts
* software delivery on read-only media
* support
* graphical UI for Windows or Linux
* periodic updates
* etc.

Just let me know. I'm located in Helsinki.


## Threat model

* OS random number generator fails (or provides numbers known to the adversary)
* CPU hardware random number generator fails (or provides numbers known to the adversary)
* Issues related to cloning a virtual machine and running the tool inside a VM

Threats outside the scope:

* Used Rust crates compromised
* Development or building tools or environment compromised resulting in a insecure binary (I do have workaround for this, if needed)
* Tool used in an environment where adversary has root/admin access and attempts to actively interfere with the keygen


### Few notes about the operation under a virtual machine.

The hypervisor may trap rdrand and rdseed instructions. Should this happen we cannot be sure what kind of randomness would be provided. To combat against this, keygen uses three randomness sources and strong method to combine these. As a result, the randomness source quality does not really matter if one of these sources is working fine.

In virtual environment it's quite possible, that the lack of external interfaces results in low levels of entropy collected. In a Linux environment the keygen always verifies the amount of entropy in the entropy pool. The underlaying OS is probably using rdrand and/or rdseed to seed its internal random number sources. Should all these (rdrand/rdseed & cpu random) fail too, the third method (cpu jitter) provides enough entropy to provide random numbers. Besides, in such a case the keygen randomness is the least of your problems.

One challenge in virtual environments is the possibility of taking snapshots or cloning VMs. In such a case there is a theoretical possibility that the random numbers provided by the OS will be se same on VM clones until the OS reseeds the random number generator. To mitigate this, the random number generation routine is executed for *each* letter. Each execution pulls randomness from three sources, and uses the system time in the HMAC DRBG personalization string. What needs to happen for keygen in VM clones to provide the same keys? The software must be running prior to pausing and cloning the VM; hypervisor needs to trap CPU rdrand, and provide the same random numbers; the underlying CPU, mass storage, memory etc. must have identical workload; and the system time must be identical to the microsecond when the VMs are resumed..


## Randomness sources

Keygen uses three randomness sources to create seed for each letter: OS random (BCryptGenRandom in Windows, /dev/random in Linux), CPU rdrand and CPU jitter. Separate HMAC DRBG instance is used to create each letter.
```
For *each* letter:
	1. Pull 512 bits from CPU rdrand.
	2. Pull 512 bits from OS random.
	3. Push 512 bits of raw CPU jitter through SHA3-256, take the lowest 64 bits. Repeat until there is 512 bits.
	4. Use HMAC DRBG to create 64 bit random value from thse 3*512 bits. Use personalization string that contains the most accurate current time stamp.
	5. Use the random 64 bit value to pick *one single letter*.
```

### CPU Jitter Entropy Collection

This is primarily to ensure random passwords even if the CPU and OS and somehow compromised.
Entropy is collected by running the following contraption until 512 bits are collected.
```
        let start = std::time::Instant::now();
        let end = std::time::Instant::now();
        let time_diff1 = end.duration_since(start).as_nanos() as u64;

        let start = std::time::Instant::now();
        let end = std::time::Instant::now();
        let time_diff2 = end.duration_since(start).as_nanos() as u64;

        if time_diff1 != time_diff2 {
            if time_diff1 > time_diff2 {
                bit_vector.add_bit(true);
            } else {
                bit_vector.add_bit(false);
            }
        }
```
On Windows hosts the resulting data has approx 6-7 bits of entropy per byte. Pushing this through Keccak results in proper random numbers even if there is only 1 bit of entroy per byte.

Comparison of Dieharder p-values for relatively small amount of data (100 M u64 values, or 800 MB raw data) shows that there are no apparent weaknesses when compared to OS random or CPU rdrand.

![Dieharder p-values](dieharder-results/p-values.png?raw=true "Title")


## License
(c) 2023 TuningSweeper.

For hobbyists, released under GNU AGPLv3 License.

For business/commercial/other use, check with me. (seriously, we can work something out. and if not this, maybe something else..)
