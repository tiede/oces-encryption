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
 * OcesSigning.java
 *
 * Created on 20. december 2006, 17:42
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package dk.tiede.oces;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

/**
 *
 * @author Kim Tiedemann
 */
public class OcesSigning {

    private File pkcs12File;

    private String pkcs12Password;

    private PrivateKey privateKey;
    
    private String privateKeyPassword;
    
    private X509Certificate certificate;
    
    /** Creates a new instance of OcesEncrypter */
    private OcesSigning(File pkcs12File, String pkcs12password, String privateKeyPassword) {
        this.pkcs12File = pkcs12File;
        this.pkcs12Password = pkcs12password;
        this.privateKeyPassword = privateKeyPassword;
    }
        
    public static OcesSigning newInstance(File pkcs12File, String pkcs12password, String privateKeyPassword) throws OcesException {
        OcesSigning signer = new OcesSigning(pkcs12File, pkcs12password, privateKeyPassword);
        signer.initialise();
        return signer;
    }
    
    private void initialise() throws OcesException {
        if (pkcs12File != null && pkcs12Password != null) {
            try {
                KeyStore keyStore = PKCS12Util.getPKCS12KeyStore(pkcs12File, pkcs12Password);
                certificate = PKCS12Util.getCertificateFromPKCS12KeyStore(keyStore, pkcs12Password);
                privateKey = PKCS12Util.getPrivateKey(keyStore, certificate, privateKeyPassword);
            } catch (Exception ex) {
                throw new OcesException();
            }
        }
    }
    
    public void sign(File fileToSign, File signFile) {
        try {
            byte[] hash = SHA1Util.getSHA1DigestFromFile(fileToSign);
            
            String sigAlg = certificate.getSigAlgName();
            Signature signature = Signature.getInstance(sigAlg);
            signature.initSign(privateKey);
            
            signature.update(hash);
            byte[] sign = signature.sign();
            
            FileOutputStream out = new FileOutputStream(signFile);
            out.write(sign);
            out.close();
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
    }    
}
