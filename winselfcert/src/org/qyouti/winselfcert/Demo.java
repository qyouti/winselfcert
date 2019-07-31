/*
 * Copyright 2019 Leeds Beckett University.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.qyouti.winselfcert;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import static org.qyouti.winselfcert.WindowsCertificateGenerator.CRYPT_USER_PROTECTED;
import static org.qyouti.winselfcert.WindowsCertificateGenerator.MS_ENH_RSA_AES_PROV;
import static org.qyouti.winselfcert.WindowsCertificateGenerator.PROV_RSA_AES;



/**
 * Demonstration 'main' class which will generate a self-signed certificate, use its private key to
 * sign some data, use its public key to verify that signiture, use its public key to encrypt some
 * data, use its private key to decrypt it and finally delete the certificate and its keys.
 * 
 * For experimentation there is also a method that can save the public key to an OpenPGP format file.
 * 
 * @author maber01
 */
public class Demo
{


  /**
   * Encrypt a byte array to a new byte array using RSA
   * @param message The 'plain text'.
   * @param k The public key to use.
   * @return The cipher text.
   * @throws GeneralSecurityException JCA type problem
   * @throws IOException Problem with transmission of data
   */
  public byte[] encryptRSA(byte[] message, PublicKey k)
          throws GeneralSecurityException, IOException
  {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, k);
    return cipher.doFinal(message);
  }

  /**
   * Decrypt a byte array to a new byte array using RSA
   * @param message The cipher text.
   * @param k The private key to use.
   * @return The plain text.
   * @throws GeneralSecurityException JCA type problem
   * @throws IOException Problem with transmission of data
   */
  public byte[] decryptRSA(byte[] message, PrivateKey k)
          throws GeneralSecurityException, IOException
  {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.DECRYPT_MODE, k);
    return cipher.doFinal(message);
  }

  /**
   * Create an SHA256withRSA signature
   * @param plainText The message to sign
   * @param k The private key to use.
   * @return A base 64 encoded signature
   * @throws Exception If problem occurs with JCA.
   */
  public String sign(String plainText, PrivateKey k)
          throws Exception
  {
    Signature privateSignature = Signature.getInstance("SHA256withRSA");
    privateSignature.initSign(k);
    privateSignature.update(plainText.getBytes(UTF_8));
    byte[] signature = privateSignature.sign();
    return Base64.getEncoder().encodeToString(signature);
  }

  /**
   * Verify an SHA256withRSA signature
   * @param plainText The message that was supposedly signed
   * @param signature The signature, base64 encoded
   * @param k The public key to use.
   * @return true if the signature passed the test
   * @throws Exception If problem occurs with JCA.
   */
  public boolean verify(String plainText, String signature, PublicKey k)
          throws Exception
  {
    Signature publicSignature = Signature.getInstance("SHA256withRSA");
    publicSignature.initVerify(k);
    publicSignature.update(plainText.getBytes(UTF_8));
    byte[] signatureBytes = Base64.getDecoder().decode(signature);
    return publicSignature.verify(signatureBytes);
  }

  /**
   * Find the secret data in the public key, build OpenPGP structures to hold them and
   * save a public key packet to the file. This method alone is dependent on bouncycastle
   * being in the class path.
   * 
   * @param pubk The public key to save.
   * @param file The file where the data will be saved.
   */
  public void savePublicKey(PublicKey pubk, File file)
  {
    RSAPublicKey rsapubk;
    rsapubk = (RSAPublicKey) pubk;
    System.out.println(rsapubk);

    try
    {
      BCPGOutputStream os = new BCPGOutputStream(new FileOutputStream(file));
      RSAPublicBCPGKey key = new RSAPublicBCPGKey(rsapubk.getModulus(), rsapubk.getPublicExponent());
      PublicKeyPacket packet = new PublicKeyPacket(PublicKeyPacket.RSA_GENERAL, new Date(System.currentTimeMillis()), key);
      packet.encode(os);
      os.close();
    }
    catch (Exception ex)
    {
      Logger.getLogger(Demo.class.getName()).log(Level.SEVERE, null, ex);
    }
  }

  /**
   * Create a single self-signed certificate in the Windows Cryptography subsystem and run a set of trial 
   * operations with it, using JCA and Sun's MSCAPI security provider. If exceptions occur they will be
   * printed to standard error and the demo will be stopped.
   * @param args Ignored.
   */
  public static void main(String[] args)
  {
    Demo inst = new Demo();
    PublicKey pubk;
    PrivateKey prik;

    byte[] crypt;
    byte[] decrypt;
    String plaintext = "Hello Mr Robot";
    String sig;
    String decrypttext;
    BigInteger serial;

    WindowsCertificateGenerator wcg = new WindowsCertificateGenerator();
    try
    {
      serial = wcg.generateSelfSignedCertificate(
              "CN=Test",
              "qyouti-" + UUID.randomUUID().toString(),
              MS_ENH_RSA_AES_PROV,
              PROV_RSA_AES,
              true,
              2048,
              CRYPT_USER_PROTECTED
      );
      if (serial == null)
      {
        System.out.println("Failed to make certificate.");
        return;
      }
      else
      {
        System.out.println("Serial number = " + serial.toString(16));
      }

      prik = wcg.getPrivatekey();
      pubk = wcg.getPublickey();

      sig = inst.sign(plaintext, prik);
      System.out.println("Did signature verify? " + inst.verify(plaintext, sig, pubk));

      crypt = inst.encryptRSA(plaintext.getBytes(), pubk);
      decrypt = inst.decryptRSA(crypt, prik);
      decrypttext = new String(decrypt);
      System.out.println("Decrypted text: " + decrypttext);

      if (plaintext.equals(decrypttext))
      {
        System.out.println("Decrypted text matches original plain text");
      }
      else
      {
        System.out.println("Decrypted text DOES NOT MATCH original plain text");
      }

      wcg.getKeyStore().deleteEntry(wcg.getAlias());
      System.out.println("Deleted Certificate");
    }
    catch (Exception e)
    {
      e.printStackTrace(System.out);
    }
  }
}
