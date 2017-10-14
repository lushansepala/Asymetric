/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package encryptdcrypt;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 *
 * @author lenovo
 */
public class Gkeys {
    
    private KeyPairGenerator keyG;
    private KeyPair pair;
    private PrivateKey PKey;
    private PublicKey PubKey;
    
    public Gkeys(int keylength) throws NoSuchAlgorithmException, NoSuchProviderException {
        this.keyG = KeyPairGenerator.getInstance("RSA");
        this.keyG.initialize(keylength);
    }

    public void createKeys() {
        this.pair = this.keyG.generateKeyPair();
        this.PKey = pair.getPrivate();
        this.PubKey = pair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return this.PKey;
    }

    public PublicKey getPublicKey() {
        return this.PubKey;
    }

    public void writeToFile(String path, byte[] key) throws IOException {
        File h = new File(path);
        h.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(h);
        fos.write(key);
        fos.flush();
        fos.close();
    }


    
}
