Encryption
==========

This is a very simple Maven project that implements the following obfuscation
(back and forth) over a string value:

* RSA encrypion
* Base64 encoding
* URL encoding

The example was based on the one exposed on `this JavaDigest's blog post`_.

How to execute the example
--------------------------

.. code:: bash

   ~$ git clone git@github.com:ariel-rios-movile/encoding.git
   ~$ cd encryption
   ~/encryption$ mvn clean install -P prod
   ~/encryption$ java -cp .:./target/lib:./target/lib/commons-codec-1.4.jar:./target/classes com.movile.encryption.EncryptionExample

.. _`this JavaDigest's blog post`: https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
