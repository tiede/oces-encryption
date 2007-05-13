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
 * SHA1Util.java
 *
 * Created on 22. februar 2007, 08:29
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package dk.tiede.oces;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author tiedekim
 */
public class SHA1Util {
    
    /** Creates a new instance of SHA1Util */
    private SHA1Util() {
    }
    
    public static byte[] getSHA1DigestFromFile(File inFile) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        FileInputStream in = new FileInputStream(inFile);
        byte[] buffer = new byte[1024];
        int bytesRead = in.read(buffer);
        
        while (bytesRead != -1)
        {
            digest.update(buffer, 0, bytesRead);   
            bytesRead = in.read(buffer);
        }
        
        in.close();
        return digest.digest();
    }
    
}
