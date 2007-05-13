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
 * OcesEncrypterTest.java
 * JUnit based test
 *
 * Created on 17. december 2006, 16:32
 */

package dk.tiede.oces;

import dk.tiede.oces.OcesDecrypter;
import dk.tiede.oces.OcesEncrypter;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import junit.framework.*;

/**
 *
 * @author Kim Tiedemann
 */
public class OcesCipheringTest extends TestCase {
    
    private OcesEncrypter encrypter;
    private OcesDecrypter decrypter;
    
    public OcesCipheringTest(String testName) {
        super(testName);
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
        
    }
    
    public void testEncryption() throws Exception {
        encrypter = OcesEncrypter.newInstance(new File("TestMOCES3.pfx.p12"), "Test1234");
        decrypter = OcesDecrypter.newInstance(new File("TestMOCES3.pfx.p12"), "Test1234", "Test1234");
        
        File plainFile = new File("test.txt");
        File encodedFile = new File("test.enc");
        File decodedFile = new File("test.out");
        encrypter.encryptFile(plainFile, encodedFile);
        decrypter.decryptFile(encodedFile, decodedFile);
        
        assertTrue(compareFiles(plainFile, decodedFile));
    }
    
    public void testEncryptionWithCertificationFile() throws Exception {
        encrypter = OcesEncrypter.newInstance(new File("TestMOCES3.cer"));
        decrypter = OcesDecrypter.newInstance(new File("TestMOCES3.pfx.p12"), "Test1234", "Test1234");
        
        File plainFile = new File("test.txt");
        File encodedFile = new File("testCer.enc");
        File decodedFile = new File("testCer.out");
        encrypter.encryptFile(plainFile, encodedFile);
        decrypter.decryptFile(encodedFile, decodedFile);
        
        assertTrue(compareFiles(plainFile, decodedFile));
    }
    
    public boolean compareFiles(File f1, File f2) throws Exception {
        boolean result = true;
        InputStream s1 = new FileInputStream(f1);
        InputStream s2 = new FileInputStream(f2);
        
        try {
            byte b1;
            byte b2;
            while ((b1 = (byte)s1.read()) != -1) {
                b2 = (byte)s2.read();
                if (b1 != b2) {
                    return false;
                }
            }
        } finally {
            s1.close();
            s2.close();
        }
        
        return true;
    }
}
