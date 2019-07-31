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

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author maber01
 */
public class Demo
{

  public Demo()
  {
  }

  public byte[] encryptRSA(byte[] message, PublicKey k)
          throws GeneralSecurityException, IOException
  {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, k);
    return cipher.doFinal(message);
  }

  public byte[] decryptRSA(byte[] message, PrivateKey k)
          throws GeneralSecurityException, IOException
  {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.DECRYPT_MODE, k);
    return cipher.doFinal(message);
  }

  public String sign(String plainText, PrivateKey k)
          throws Exception
  {
    Signature privateSignature = Signature.getInstance("SHA256withRSA");
    privateSignature.initSign(k);
    privateSignature.update(plainText.getBytes(UTF_8));
    byte[] signature = privateSignature.sign();
    return Base64.getEncoder().encodeToString(signature);
  }

  public boolean verify(String plainText, String signature, PublicKey k)
          throws Exception
  {
    Signature publicSignature = Signature.getInstance("SHA256withRSA");
    publicSignature.initVerify(k);
    publicSignature.update(plainText.getBytes(UTF_8));
    byte[] signatureBytes = Base64.getDecoder().decode(signature);
    return publicSignature.verify(signatureBytes);
  }

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
