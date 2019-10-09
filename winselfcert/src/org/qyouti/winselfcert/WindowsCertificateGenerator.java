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
 * Used to access the winselfcert native library which will interface with the Microsoft Windows 
 * Cryptography API (CAPI) and create a self-signed digital certificate with key pair. When Sun's 
 * MSCAPI security provider is used to create self-signed certificates that code hard-wires some 
 * of the options.  Rather than implement a whole new security provider to fix that small limitation
 * this class operates outside of the Java Cryptography Architecture to call into CAPI but the 
 * resources it creates (certificate and keys) can be used within the JCA using the standard MSCAPI 
 * provider. 
 * 
 * The general patter of usage is this:
 * 
 * 1) Set up - ensure that the shared native library is in the library path.
 * 2) Construct an instance of this class.
 * 3) Call generateSelfSignedCertificate()
 * 4) Use 'get' methods to fetch the certificate and keys that were created using the MSCAPI provider.
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

/**
 * Loads the native library unless already loaded.
 * @return 
 */
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

  /**
   * Typically one instance is constructed to generate one certificate.
   */
  public WindowsCertificateGenerator()
  {
    try
    {
      keystore = KeyStore.getInstance(KEYSTORETYPE, WINPROVIDER);
      keystore.load(null, null);
    }
    catch (Exception ex)
    {
      //Logger.getLogger(WindowsCertificateGenerator.class.getName()).log(Level.SEVERE, null, ex);
      keystore = null;
    }
  }

    /**
   * The JCA keystore where the generated data will be found.
   * @return A JCA KeyStore implemented by Sun's MSCAPI provider.
   */
  public KeyStore getKeyStore()
  {
    return keystore;
  }

  /**
   * The alias of the certificate that was just created.
   * @return Null if no certificate generated.
   */
  public String getAlias()
  {
    return alias;
  }

  /**
   * JCA Certificate representing the certificate that was generated.
   * @return Null if no certificate generated.
   */
  public Certificate getCertificate()
  {
    return certificate;
  }

  /**
   * JCA PublicKey from the certificate that was generated.
   * @return Null if no certificate generated.
   */
  public PublicKey getPublickey()
  {
    return (PublicKey) publickey;
  }

  /**
   * JCA PrivateKey from the certificate that was generated. Note that it will be impossible to access the actual
   * data of the key (e.g. modulus) from this class. It holds a handle onto a data structure held in the Windows 
   * security subsystem so all decryption or signing operations must take place within that subsystem via JCA
   * and Sun's MSCAPI provider.
   * @return Null if no certificate generated.
   */
  public PrivateKey getPrivatekey()
  {
    return privatekey;
  }

  
  
  
  /**
   * Search the (MSCAPI provider) keystore for a certificate with a
   * given serial number and retrieve the alias.
   * @param serial Serial number of the desired certificate.
   * @return The alias used in the CAPI store for the given certificate or null if not found.
   * @throws GeneralSecurityException
   * @throws IOException 
   */
  private String findAliasFromSerialNumber(BigInteger serial)
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

  /**
   * Generate a self-signed certificate and fetch references to it and its nested pair of keys
   * using the MSCAPI security provider.
   * @param commonname X500 common name used in the certificate.
   * @param containername A unique container name.
   * @param providername This is the CAPI provider name NOT a JCA provider name. Use one of the static constants, 
   * MS_*, defined in this class.
   * @param providertype This is the CAPI provider type. Use one of the static constants, PROV_*, defined in this class.
   * @param keyexchange Can't remember what this is!
   * @param keybitsize Size in bits of key - consult MS documentation for the limitations of various providers.
   * @param keyflags This is the crucial functionality lacking in Sun's MSCAPI provider. Use bitwise combination of CRYPT_* constants.
   * @return A BigInteger representation of Microsoft's locally unique serial number or null if no certificate was created.
   * @throws WindowsCertificateException Thrown if a CAPI error occurs within the native code.
   */
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


  /**
   * This is the one native method in the library which is called by the matching public Java method.
   * @param commonname X500 common name used in the certificate.
   * @param containername A unique container name.
   * @param providername This is the CAPI provider name NOT a JCA provider name.
   * @param providertype This is the CAPI provider type. 
   * @param keyexchange Can't remember what this is!
   * @param keybitsize Size in bits of key.
   * @param keyflags Flags indicating various options.
   * @return A BigInteger representation of Microsoft's locally unique serial number or null if no certificate was created.
   * @throws WindowsCertificateException Thrown if a CAPI error occurs within the native code.
   */
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
