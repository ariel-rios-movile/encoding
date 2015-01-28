package com.movile.encryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.net.URLCodec;

/**
 * @author JavaDigest
 *
 */
public class EncryptionExample {

    /**
     * String to hold name of the encryption algorithm.
     */
    public static final String ALGORITHM = "RSA";

    /**
     * Key algorithm size.
     */
    public static final int KEY_SIZE = 1024;

    /**
     * String to hold the name of the private key file.
     */
    public static final String PRIVATE_KEY_FILE = "./keys/private.key";

    /**
     * String to hold name of the public key file.
     */
    public static final String PUBLIC_KEY_FILE = "./keys/public.key";

    /**
     * Generate key which contains a pair of private and public key using 1024
     * bytes. Store the set of keys in Prvate.key and Public.key files.
     *
     * @throws NoSuchAlgorithmException TODO
     * @throws IOException TODO
     */
    public static void generateKey() throws IOException,
            NoSuchAlgorithmException {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(KEY_SIZE);
        final KeyPair key = keyGen.generateKeyPair();

        File privateKeyFile = new File(PRIVATE_KEY_FILE);
        File publicKeyFile = new File(PUBLIC_KEY_FILE);

        // Create files to store public and private key
        if (privateKeyFile.getParentFile() != null) {
            privateKeyFile.getParentFile().mkdirs();
        }
        privateKeyFile.createNewFile();

        if (publicKeyFile.getParentFile() != null) {
            publicKeyFile.getParentFile().mkdirs();
        }
        publicKeyFile.createNewFile();

        // Saving the Public key in a file
        ObjectOutputStream publicKeyOS = new ObjectOutputStream(
                new FileOutputStream(publicKeyFile));
        publicKeyOS.writeObject(key.getPublic());
        publicKeyOS.close();

        // Saving the Private key in a file
        ObjectOutputStream privateKeyOS = new ObjectOutputStream(
                new FileOutputStream(privateKeyFile));
        privateKeyOS.writeObject(key.getPrivate());
        privateKeyOS.close();
    }

    /**
     * The method checks if the pair of public and private key has been
     * generated.
     *
     * @return flag indicating if the pair of keys were generated.
     */
    public static boolean areKeysPresent() {

        File privateKey = new File(PRIVATE_KEY_FILE);
        File publicKey = new File(PUBLIC_KEY_FILE);

        return privateKey.exists() && publicKey.exists();
    }

    /**
     * Encrypt the plain text using public key.
     *
     * @param text
     *            : original plain text
     * @param key
     *            :The public key
     * @return Encrypted text
     * @throws NoSuchPaddingException TODO
     * @throws NoSuchAlgorithmException TODO
     * @throws InvalidKeyException TODO
     * @throws BadPaddingException TODO
     * @throws IllegalBlockSizeException TODO
     */
    public static byte[] encrypt(String text, PublicKey key)
        throws NoSuchAlgorithmException, NoSuchPaddingException,
        InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        // RSA encryption

        byte[] cipherText = null;
        // get an RSA cipher object and print the provider
        final Cipher cipher = Cipher.getInstance(ALGORITHM);
        // encrypt the plain text using the public key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(text.getBytes());

        System.out.println(">>> Encryption step");
        System.out.println("1. RSA encryption: " + new String(cipherText));

        // Encoding to Base64

        cipherText = Base64.encodeBase64(cipherText);
        System.out.println("2. Base64 encoding: " + new String(cipherText));

        // Applying URLEncode

        URLCodec codec = new URLCodec();
        cipherText = codec.encode(cipherText);
        System.out.println("3. URL encoding: " + new String(cipherText));
        System.out.println("<<< Encryption step");

        return cipherText;
    }

    /**
     * Decrypt text using private key.
     *
     * @param text
     *            :encrypted text
     * @param key
     *            :The private key
     * @return plain text
     * @throws NoSuchPaddingException TODO
     * @throws NoSuchAlgorithmException TODO
     * @throws InvalidKeyException TODO
     * @throws BadPaddingException TODO
     * @throws IllegalBlockSizeException TODO
     * @throws DecoderException TODO
     */
    public static String decrypt(byte[] text, PrivateKey key)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, DecoderException {

        byte[] dectyptedText = null;

        // Decoding URLEncode

        System.out.println(">>> Decryption step");

        URLCodec codec = new URLCodec();
        dectyptedText = codec.decode(text);
        System.out.println("1. URL decoding: " + new String(dectyptedText));

        // Base64 decode

        dectyptedText = Base64.decodeBase64(dectyptedText);
        System.out.println("2. Base64 decoding: " + new String(dectyptedText));

        // RSA decryption

        // get an RSA cipher object and print the provider
        final Cipher cipher = Cipher.getInstance(ALGORITHM);

        // decrypt the text using the private key
        cipher.init(Cipher.DECRYPT_MODE, key);
        dectyptedText = cipher.doFinal(dectyptedText);
        System.out.println("3. RSA decryption: " + new String(dectyptedText));

        System.out.println("<<< Decryption step");

        return new String(dectyptedText);
    }

    /**
     * Test the EncryptionUtil
     */
    public static void main(String[] args) {

        FileInputStream fileInput = null;
        ObjectInputStream inputStream = null;
        final String originalText = "Text to be encrypted ";

        try {

            // Check if the pair of keys are present else generate those.
            if (!areKeysPresent()) {
                // Method generates a pair of keys using the RSA algorithm and
                // stores it
                // in their respective files
                generateKey();
            }

            // Encrypt the string using the public key
            inputStream = new ObjectInputStream(new FileInputStream(
                    PUBLIC_KEY_FILE));
            final PublicKey publicKey = (PublicKey) inputStream.readObject();
            final byte[] cipherText = encrypt(originalText, publicKey);

            // Decrypt the cipher text using the private key.

            fileInput = new FileInputStream(PRIVATE_KEY_FILE);
            inputStream = new ObjectInputStream(fileInput);
            final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
            final String plainText = decrypt(cipherText, privateKey);

            // Printing the Original, Encrypted and Decrypted Text
            System.out.println("Original: " + originalText);
            System.out.println("Encrypted: " + new String(cipherText));
            System.out.println("Decrypted: " + plainText);

            fileInput.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
