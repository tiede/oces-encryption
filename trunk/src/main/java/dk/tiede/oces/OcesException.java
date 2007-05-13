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
 * OcesException.java
 *
 * Created on 17. december 2006, 16:18
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package dk.tiede.oces;

/**
 *
 * @author Kim Tiedemann
 */
public class OcesException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>OcesException</code> without detail message.
     */
    public OcesException() {
    }
    
    
    /**
     * Constructs an instance of <code>OcesException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public OcesException(String msg) {
        super(msg);
    }
}
