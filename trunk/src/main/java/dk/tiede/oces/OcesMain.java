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
 * OcesMain.java
 *
 * Created on 28. december 2006, 17:39
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package dk.tiede.oces;

import java.io.File;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.ExampleMode;

import org.kohsuke.args4j.Option;

/**
 *
 * @author Kim Tiedemann
 */
public class OcesMain {
    
    enum Mode {ENCRYPT, DECRYPT, SIGN, VERIFY}
    
    @Option(name="-mode", usage="Set the mode of the program ie the program will decrypt, encrypt, sign or verify", metaVar="encrypt|decrypt|sign|verify", required=true)
    private Mode mode;
    
    @Option(name="-source", usage="The file used as a source for processing", required=true)
    private File sourceFile;

    @Option(name="-destination", usage="The destination file to store the result in (mandatory when mode=encrypt|decrypt|sign)")
    private File destinationFile;
    
    @Option(name="-pkcs12", usage="The pkcs12 file containing both the public and private key (mandatory when mode=decrypt|sign, optional when mode=encrypt|verify)")
    private File pkcs12File;
    
    @Option(name="-password", usage="The password used for accessing the pkcs12 file (mandatory when mode=decrypt|sign, optional when mode=encrypt|verify)")
    private String pkcs12Password;
    
    @Option(name="-certificate", usage="The X509 certificate file that contains the public key")
    private File certificateFile;
    
    @Option(name="-signature", usage="The file containing the signature of a signed file")
    private File signatureFile;
    
        
    /** Creates a new instance of OcesMain */
    public OcesMain() {
    }
    
    public void doMain(String args[]) throws Exception {
        CmdLineParser parser = new CmdLineParser(this);
        parser.setUsageWidth(80);
        
        try {
            parser.parseArgument(args);
            
            if (mode == Mode.ENCRYPT) {
                OcesEncrypter encrypter = null;
                if (pkcs12File != null && pkcs12Password != null) {
                    encrypter = OcesEncrypter.newInstance(pkcs12File, pkcs12Password);
                } 
                else if (certificateFile != null) {
                    encrypter = OcesEncrypter.newInstance(certificateFile);
                }
                else {
                    printError("When mode=encrypt the parameters (pkcs12,password) or the parameter (certificate) must be set to access a public key");
                }
                
                if (encrypter != null) {
                    if (destinationFile  != null) {
                        encrypter.encryptFile(sourceFile, destinationFile);
                        System.out.println("The file " + sourceFile + " was succesfully encrypted to file " + destinationFile);
                    }
                    else {
                        printError("The destination file parameter must be given when mode=encrypt");
                    }
                }
            }
            else if (mode == Mode.DECRYPT) {
                OcesDecrypter decrypter = null;
                if (pkcs12File != null && pkcs12Password != null) {
                    decrypter = OcesDecrypter.newInstance(pkcs12File, pkcs12Password, pkcs12Password);
                    if (destinationFile != null) {
                        decrypter.decryptFile(sourceFile, destinationFile);
                        System.out.println("The file " + sourceFile + " was succesfully decrypted to file " + destinationFile);
                    }
                    else {
                        printError("The destination file parameter must be given when mode=decrypt");
                    }
                }
                else {
                    printError("When mode=decrypt the parameters (pkcs12,password) must be set to access the private key");
                }
            }
            else if (mode == Mode.SIGN) {
                OcesSigning signer = null;
                if (pkcs12File != null && pkcs12Password != null) {
                    signer = OcesSigning.newInstance(pkcs12File, pkcs12Password, pkcs12Password);
                } 
                else {
                    printError("When mode=sign the parameters (pkcs12,password) must be set to access the private key");  
                }
                
                if (signer != null) {
                    if (destinationFile  != null) {
                        signer.sign(sourceFile, destinationFile);
                        System.out.println("The file " + sourceFile + " was succesfully signed and the signature is stored in " + destinationFile);
                    }
                    else {
                        printError("The destination file parameter must be given when mode=sign");
                    }
                }
            }
            else if (mode == Mode.VERIFY) {
                OcesSigningVerifier verifier = null;
                if (pkcs12File != null && pkcs12Password != null) {
                    verifier = OcesSigningVerifier.newInstance(pkcs12File, pkcs12Password);
                } 
                else if (certificateFile != null) {
                    verifier = OcesSigningVerifier.newInstance(certificateFile);
                }
                else {
                    printError("When mode=verify the parameters (pkcs12,password) or the parameter (certificate) must be set to access the public key");  
                }
                
                if (verifier != null) {
                    if (signatureFile  != null) {
                        boolean verified = verifier.verify(sourceFile, signatureFile);
                        if (verified) {
                            System.out.println("The file and signature is valid");
                        }
                        else {
                            System.out.println("The file and signature is NOT valid");
                        }
                    }
                    else {
                        printError("The signature parameter must be given when mode=verify");
                    }
                }
            }
        } catch (CmdLineException ex) {
            printError(ex.getMessage());
            printUsage(parser);
            return;
        }
    }
    
    public static void main (String args[]) throws Exception {
        OcesMain main = new OcesMain();
        main.doMain(args);
    }
    
    private void printUsage(CmdLineParser parser) {
        System.err.println("java dk.tiede.oces.OcesMain [options...] arguments...");
        parser.printUsage(System.err);
        System.err.println();
        System.err.println("  Example: java dk.tiede.oces.OcesMain"+parser.printExample(ExampleMode.ALL));
    }
    
    private void printError(String errorMessage) {
        System.err.println(errorMessage);
    }
    
}
