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
 * OcesDecrypter.java
 *
 * Created on 17. december 2006, 17:29
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package dk.tiede.oces;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Kim Tiedemann
 */
public class OcesDecrypter extends OcesCiphering {
    
    private File pkcs12File;
    private String pkcs12Password;
    private String privateKeyPassword;
    private PrivateKey privateKey;
    
    /** Creates a new instance of OcesEncrypter */
    private OcesDecrypter(File pkcs12File, String pkcs12password, String privateKeyPassword) {
        this.pkcs12File = pkcs12File;
        this.pkcs12Password = pkcs12password;
        this.privateKeyPassword = privateKeyPassword;
    }
    
    public static OcesDecrypter newInstance(File pkcs12File, String pkcs12Password, String privateKeyPassword) throws OcesException {
        OcesDecrypter decrypter = new OcesDecrypter(pkcs12File, pkcs12Password, privateKeyPassword);
        decrypter.initialise();
        return decrypter;
    }
    
    private void initialise() throws OcesException {
        if (pkcs12File != null && pkcs12Password != null) {
            try {
                KeyStore keyStore = PKCS12Util.getPKCS12KeyStore(pkcs12File, pkcs12Password);
                X509Certificate certificate = PKCS12Util.getCertificateFromPKCS12KeyStore(keyStore, pkcs12Password);
                privateKey = PKCS12Util.getPrivateKey(keyStore, certificate, privateKeyPassword);
            } catch (Exception ex) {
                throw new OcesException();
            }
        }
    }
    
    public void decryptFile(File fileToBeDecrypted, File decryptedFile) {
        try {
            DataInputStream in = new DataInputStream(new FileInputStream(fileToBeDecrypted));
            int length = in.readInt();
            byte[] wrappedKey = new byte[length];
            in.read(wrappedKey, 0, length);
            
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.UNWRAP_MODE, privateKey);
            Key key = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
            
            OutputStream out = new FileOutputStream(decryptedFile);
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key, cipher.getParameters());
            
            crypt(in, out, cipher);
            
            in.close();
            out.close();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        } catch (NoSuchPaddingException nspe) {
            nspe.printStackTrace();
        } catch (InvalidKeyException ike) {
            ike.printStackTrace();
        } catch (IllegalBlockSizeException ibse) {
            ibse.printStackTrace();
        } catch (GeneralSecurityException gse) {
            gse.printStackTrace();
        }
    }
    
}
