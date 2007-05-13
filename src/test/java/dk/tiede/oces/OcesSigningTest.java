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
 * OcesSigningTest.java
 * JUnit based test
 *
 * Created on 20. december 2006, 17:59
 */

package dk.tiede.oces;

import dk.tiede.oces.OcesSigning;
import dk.tiede.oces.OcesSigningVerifier;
import java.io.File;
import junit.framework.*;

/**
 *
 * @author Kim Tiedemann
 */
public class OcesSigningTest extends TestCase {
    
    public OcesSigningTest(String testName) {
        super(testName);
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }
    
    public void testSigning() throws Exception {
        OcesSigning signing = OcesSigning.newInstance(new File("TestMOCES3.pfx.p12"), "Test1234", "Test1234");
        OcesSigningVerifier verifier = OcesSigningVerifier.newInstance(new File("TestMOCES3.pfx.p12"), "Test1234");
        File plainFile = new File("test.txt");
        File signFile = new File("test.sig");
        signing.sign(plainFile, signFile);
        assertTrue("Signature must be verified", verifier.verify(plainFile, signFile));
    }
    
    public void testSigningAndVerifyWithPublicCert() throws Exception {
        OcesSigning signing = OcesSigning.newInstance(new File("TestMOCES3.pfx.p12"), "Test1234", "Test1234");
        OcesSigningVerifier verifier = OcesSigningVerifier.newInstance(new File("TestMOCES3.cer"));
        File plainFile = new File("test.txt");
        File signFile = new File("test.sig");
        signing.sign(plainFile, signFile);
        assertTrue("Signature must be verified", verifier.verify(plainFile, signFile));
    }
    
    public void testSigningAndVerifyWithPublicCertFail() throws Exception {
        OcesSigning signing = OcesSigning.newInstance(new File("TestMOCES3.pfx.p12"), "Test1234", "Test1234");
        OcesSigningVerifier verifier = OcesSigningVerifier.newInstance(new File("KimBjørnTiedemann.cer"));
        File plainFile = new File("test.txt");
        File signFile = new File("test.sig");
        signing.sign(plainFile, signFile);
        assertFalse("Signature must NOT be verified", verifier.verify(plainFile, signFile));
    }
}
