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
 * OcesSigningVerifier.java
 *
 * Created on 21. december 2006, 19:56
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package dk.tiede.oces;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 *
 * @author Kim Tiedemann
 */
public class OcesSigningVerifier {
    
    private File pkcs12File;

    private String pkcs12Password;

    private PublicKey publicKey;
    
    private X509Certificate certificate;
    
    private File x509CertificateFile;
    
    /** Creates a new instance of OcesEncrypter */
    private OcesSigningVerifier(File pkcs12File, String pkcs12password) {
        this.pkcs12File = pkcs12File;
        this.pkcs12Password = pkcs12password;
    }
    
    private OcesSigningVerifier(File certificateFile) {
        this.x509CertificateFile = certificateFile;
    }
        
    public static OcesSigningVerifier newInstance(File pkcs12File, String pkcs12password) throws OcesException {
        OcesSigningVerifier verifier = new OcesSigningVerifier(pkcs12File, pkcs12password);
        verifier.initialise();
        return verifier;
    }
    
    public static  OcesSigningVerifier newInstance(File x509CertificateFile) throws OcesException {
        OcesSigningVerifier verifier = new OcesSigningVerifier(x509CertificateFile);
        verifier.initialise();
        return verifier;
    }
    
    private void initialise() throws OcesException {
        if (pkcs12File != null && pkcs12Password != null) {
            try {
                KeyStore keyStore = PKCS12Util.getPKCS12KeyStore(pkcs12File, pkcs12Password);
                certificate = PKCS12Util.getCertificateFromPKCS12KeyStore(keyStore, pkcs12Password);
                publicKey = certificate.getPublicKey();
            } catch (Exception ex) {
                throw new OcesException();
            }
        }
        else if (x509CertificateFile != null) {
            try {
                    CertificateFactory factory = CertificateFactory.getInstance("X.509");
                    certificate = (X509Certificate)factory.generateCertificate(new FileInputStream(x509CertificateFile));
                    publicKey = certificate.getPublicKey();
                } catch (FileNotFoundException ex) {
                    throw new OcesException();
                } catch (CertificateException ex) {
                    throw new OcesException();
                }
        }
    }
    
    public boolean verify(File signedFile, File signFile) {
        boolean result = false;
        try {
            String sigAlg = certificate.getSigAlgName();
            Signature signature = Signature.getInstance(sigAlg);
            
            signature.initVerify(publicKey);
            
            byte[] hash = SHA1Util.getSHA1DigestFromFile(signedFile);
            
            signature.update(hash);
            if (signature.verify(getBytesFromFile(signFile))) {
                result = true;
            }
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
        } catch (SignatureException ex) {
            ex.printStackTrace();
        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        
        return result;
    }
    
    private static byte[] getBytesFromFile(File file) throws IOException {
        InputStream is = new FileInputStream(file);
    
        // Get the size of the file
        long length = file.length();
    
        // You cannot create an array using a long type.
        // It needs to be an int type.
        // Before converting to an int type, check
        // to ensure that file is not larger than Integer.MAX_VALUE.
        if (length > Integer.MAX_VALUE) {
            // File is too large
        }
    
        // Create the byte array to hold the data
        byte[] bytes = new byte[(int)length];
    
        // Read in the bytes
        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length
               && (numRead=is.read(bytes, offset, bytes.length-offset)) >= 0) {
            offset += numRead;
        }
    
        // Ensure all the bytes have been read in
        if (offset < bytes.length) {
            throw new IOException("Could not completely read file "+file.getName());
        }
    
        // Close the input stream and return bytes
        is.close();
        return bytes;
    }


    
}
