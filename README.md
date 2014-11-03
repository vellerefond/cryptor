cryptor
=======

A triple encryption tool using the BouncyCastle implementations of <a href="http://www.cl.cam.ac.uk/~rja14/serpent.html" target="_blank">Serpent</a>, <a href="https://www.schneier.com/threefish.html" target="_blank">Threefish</a> and <a href="http://en.wikipedia.org/wiki/Advanced_Encryption_Standard" target="_blank">Rijndael (AES)</a>.

It uses the <a href="https://www.bouncycastle.org/">The Legion of the Bouncy Castle</a> implementations of the algorithms and it's API has been preferred as well, so as to avoid any exceptions regarding invalid key lengths due to the lack of the appropriate _Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files_. As such, the key lengths are always the maximum ones per algorithm. Also, the key is hashed and used as the material for the three _secret keys_ as well as for the material of the _IVs_. The chosen hashes are <a href="https://www.schneier.com/skein.html" target="_blank">Skein</a> and <a href="http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html" target="_blank">Whirlpool</a>.

    usage: java -jar cryptor.jar ( -e | -d ) [ path(s)_to_input_file(s) ] [ -o prefix{regex}suffix ]
        -e
                encrypt
        -d
                decrypt
        path(s)_to_input_file(s)
                space separated paths to input files (by default using the standard input stream)
        -o prefix{regex}suffix
                for each input file extract the regex part (if no regex has been provided, use the entire input file path)
                and prepend/append the provided prefix/suffix (by default using the standard output stream)
