// Copyright 2006 Kim Bjørn Tiedemann (www.tiede.dk and blog.tiede.dk) 
// Licensed under the Apache License, Version 2.0 (the "License"); you may not 
// use this file except in compliance with the License. 
// You may obtain a copy of the License at 
//
//   http://www.apache.org/licenses/LICENSE-2.0 
//
// Unless required by applicable law or agreed to in writing, software 
// distributed under the License is distributed on an "AS IS" BASIS, 
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
// See the License for the specific language governing permissions and 
// limitations under the License.

/*
 * PKCS12Util.java
 *
 * Created on 14. december 2006, 14:24
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package dk.tiede.oces;

import java.io.File;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Vector;
/**
 *
 * @author tiedekim
 */
public class PKCS12Util {
    
    /** Creates a new instance of PKCS12Util */
    public PKCS12Util() {
    }
    
    public static X509Certificate[] getCertificateChainFromPKCS12File(File f, String password) throws Exception
    {
        KeyStore keyStore = getPKCS12KeyStore(f, password);   
        return getCertificateChainFromPKCS12KeyStore(keyStore, password);
    }
    
    public static X509Certificate[] getCertificateChainFromPKCS12KeyStore(KeyStore keyStore, String password) throws Exception
    {
        Vector v = new Vector(0, 1);   
        X509Certificate keyEntryCert = null;
        int numberOfAlias = 0;
        int numberOfCert = 0;
        int numberOfKeyEntry = 0;
        try {
          Enumeration en = keyStore.aliases();          
          while (en.hasMoreElements()) {
            String temp = (String)en.nextElement();
            numberOfAlias++;
            if (keyStore.isKeyEntry(temp)) {              // owner
              numberOfKeyEntry++;
              keyEntryCert = (X509Certificate)keyStore.getCertificate(temp);
            }
            if (keyStore.isCertificateEntry(temp)) {
              X509Certificate cerCert;
              cerCert = (X509Certificate)keyStore.getCertificate(temp);
              v.add(cerCert);
              numberOfCert++;
            }
          }
          if ((numberOfAlias == numberOfCert + numberOfKeyEntry) & (numberOfKeyEntry == 1)) {
            if (keyEntryCert != null) {
              v.add(0, keyEntryCert);               // is owners certificate is asociated with "key entry" alias
            }
          }
          else
            throw new Exception("");
         }
        catch (Exception e) {
            
        }
        
        return (X509Certificate[])v.toArray(new X509Certificate[0]);
    }
    
    public static X509Certificate getCertificateFromPKCS12File(File f, String password) throws Exception {
        X509Certificate[] certs = getCertificateChainFromPKCS12File(f, password);
        return certs[0];
    }
    
    public static X509Certificate getCertificateFromPKCS12KeyStore(KeyStore keyStore, String password) throws Exception {
        X509Certificate[] certs = getCertificateChainFromPKCS12KeyStore(keyStore, password);
        return certs[0];
    }
    
    public static KeyStore getPKCS12KeyStore (File pkcs12File, String password) throws Exception {
        FileInputStream fis = new FileInputStream(pkcs12File);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(fis, password.toCharArray());
        fis.close();
        
        return keyStore;
    }
    
    public static PrivateKey getPrivateKey(KeyStore keyStore, X509Certificate certificate, String password) throws Exception {
        return (PrivateKey)keyStore.getKey(keyStore.getCertificateAlias(certificate), password.toCharArray());
    }
    
    public static PublicKey getPublicKey(X509Certificate certificate) {
        return certificate.getPublicKey();
    }
    
    public static void printCertificates(X509Certificate[] certificates, PrintWriter writer) {
        writer.print("TESTER");
        for(X509Certificate cert : certificates) {
            writer.println(cert.toString());
        }
        writer.flush();
    }

    protected void finalize() throws Throwable {
    }
}
