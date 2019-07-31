/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.winselfcert;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author maber01
 */
public class WindowsCertificateGenerator
{

  public static final String KEYSTORETYPE = "Windows-MY";
  public static final String WINPROVIDER = "SunMSCAPI";

  public final static String MS_DEF_PROV = "Microsoft Base Cryptographic Provider v1.0";
  public final static String MS_ENHANCED_PROV = "Microsoft Enhanced Cryptographic Provider v1.0";
  public final static String MS_STRONG_PROV = "Microsoft Strong Cryptographic Provider";
  public final static String MS_DEF_RSA_SIG_PROV = "Microsoft RSA Signature Cryptographic Provider";
  public final static String MS_DEF_RSA_SCHANNEL_PROV = "Microsoft RSA SChannel Cryptographic Provider";
  public final static String MS_DEF_DSS_PROV = "Microsoft Base DSS Cryptographic Provider";
  public final static String MS_DEF_DSS_DH_PROV = "Microsoft Base DSS and Diffie-Hellman Cryptographic Provider";
  public final static String MS_ENH_DSS_DH_PROV = "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider";
  public final static String MS_DEF_DH_SCHANNEL_PROV = "Microsoft DH SChannel Cryptographic Provider";
  public final static String MS_SCARD_PROV = "Microsoft Base Smart Card Crypto Provider";
  public final static String MS_ENH_RSA_AES_PROV = "Microsoft Enhanced RSA and AES Cryptographic Provider";
  public final static String MS_ENH_RSA_AES_PROV_XP = "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)";

  public final static int PROV_RSA_FULL = 1;
  public final static int PROV_RSA_SIG = 2;
  public final static int PROV_DSS = 3;
  public final static int PROV_FORTEZZA = 4;
  public final static int PROV_MS_EXCHANGE = 5;
  public final static int PROV_SSL = 6;
  public final static int PROV_STT_MER = 7;
  public final static int PROV_STT_ACQ = 8;
  public final static int PROV_STT_BRND = 9;
  public final static int PROV_STT_ROOT = 10;
  public final static int PROV_STT_ISS = 11;
  public final static int PROV_RSA_SCHANNEL = 12;
  public final static int PROV_DSS_DH = 13;
  public final static int PROV_EC_ECDSA_SIG = 14;
  public final static int PROV_EC_ECNRA_SIG = 15;
  public final static int PROV_EC_ECDSA_FULL = 16;
  public final static int PROV_EC_ECNRA_FULL = 17;
  public final static int PROV_DH_SCHANNEL = 18;
  public final static int PROV_SPYRUS_LYNKS = 20;
  public final static int PROV_RNG = 21;
  public final static int PROV_INTEL_SEC = 22;
  public final static int PROV_REPLACE_OWF = 23;
  public final static int PROV_RSA_AES = 24;

  public final static int CRYPT_EXPORTABLE = 0x1;
  public final static int CRYPT_USER_PROTECTED = 0x2;
  public final static int CRYPT_CREATE_SALT = 0x4;
  public final static int CRYPT_UPDATE_KEY = 0x8;
  public final static int CRYPT_NO_SALT = 0x10;
  public final static int CRYPT_PREGEN = 0x40;
  public final static int CRYPT_RECIPIENT = 0x10;
  public final static int CRYPT_INITIATOR = 0x40;
  public final static int CRYPT_ONLINE = 0x80;
  public final static int CRYPT_SF = 0x100;
  public final static int CRYPT_CREATE_IV = 0x200;
  public final static int CRYPT_KEK = 0x400;
  public final static int CRYPT_DATA_KEY = 0x800;
  public final static int CRYPT_VOLATILE = 0x1000;
  public final static int CRYPT_SGCKEY = 0x2000;
  public final static int CRYPT_ARCHIVABLE = 0x4000;
  public final static int CRYPT_FORCE_KEY_PROTECTION_HIGH = 0x8000;
  public final static int CRYPT_USER_PROTECTED_STRONG = 0x100000;

  private static boolean libloaded = false;
  private static boolean liberror = false;

  // Run this command to dump detailed info on all certificates
  // in the 'my' store.
  // certutil -v -store -user my
  private static boolean loadLibrary()
  {
    if (libloaded)
    {
      return true;
    }
    if (liberror)
    {
      return false;
    }
    try
    {
      System.loadLibrary("winselfcert");
      libloaded = true;
      return true;
    }
    catch (Exception e)
    {
      liberror = true;
      return false;
    }
  }

  KeyStore keystore = null;
  String alias;
  Certificate certificate;
  Key publickey;
  PrivateKey privatekey;

  public WindowsCertificateGenerator()
  {
    try
    {
      keystore = KeyStore.getInstance(KEYSTORETYPE, WINPROVIDER);
      keystore.load(null, null);
    }
    catch (Exception ex)
    {
      Logger.getLogger(WindowsCertificateGenerator.class.getName()).log(Level.SEVERE, null, ex);
      keystore = null;
    }
  }

  public String findAliasFromSerialNumber(BigInteger serial)
          throws GeneralSecurityException, IOException
  {
    Enumeration<String> aliases = keystore.aliases();
    String a;
    while (aliases.hasMoreElements())
    {
      a = aliases.nextElement();
      Certificate[] chain = keystore.getCertificateChain(a);
      if (chain[chain.length - 1] instanceof X509Certificate)
      {
        X509Certificate x509 = (X509Certificate) chain[chain.length - 1];
        //System.out.println( x509.getSerialNumber().toString(16) );
        if (serial.equals(x509.getSerialNumber()))
        {
          return a;
        }
      }
    }
    return null;
  }

  public BigInteger generateSelfSignedCertificate(
          String commonname,
          String containername,
          String providername,
          int providertype,
          boolean keyexchange,
          int keybitsize,
          int keyflags
  )
          throws WindowsCertificateException
  {
    alias = null;
    certificate = null;
    publickey = null;
    privatekey = null;

    if (keystore == null)
    {
      throw new WindowsCertificateException("Unable to access Windows key store.");
    }

    loadLibrary();
    byte[] serialbytes = requestCAPISelfSignedCertificate(
            commonname,
            containername,
            providername,
            providertype,
            keyexchange,
            keybitsize,
            keyflags
    );
    BigInteger serial = null;
    if (serialbytes != null && serialbytes.length > 0)
    {
      serial = new BigInteger(1, serialbytes);
    }

    try
    {
      keystore.load(null, null);
      alias = findAliasFromSerialNumber(serial);
      Certificate[] chain = keystore.getCertificateChain(alias);
      certificate = chain[chain.length - 1];
      privatekey = (PrivateKey) keystore.getKey(alias, null);
      publickey = certificate.getPublicKey();
      return serial;
    }
    catch (GeneralSecurityException | IOException ex)
    {
      Logger.getLogger(WindowsCertificateGenerator.class.getName()).log(Level.SEVERE, null, ex);
    }

    alias = null;
    certificate = null;
    publickey = null;
    privatekey = null;
    return null;
  }

  public KeyStore getKeyStore()
  {
    return keystore;
  }

  public String getAlias()
  {
    return alias;
  }

  public Certificate getCertificate()
  {
    return certificate;
  }

  public PublicKey getPublickey()
  {
    return (PublicKey) publickey;
  }

  public PrivateKey getPrivatekey()
  {
    return privatekey;
  }

  private native byte[] requestCAPISelfSignedCertificate(
          String commonname,
          String containername,
          String providername,
          int providertype,
          boolean keyexchange,
          int keybitsize,
          int keyflags
  )
          throws WindowsCertificateException;

}
