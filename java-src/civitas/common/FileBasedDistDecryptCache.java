/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */ 
package civitas.common;

import java.io.*;

import jif.lang.LabelUtil;
import jif.lang.Principal;
import civitas.crypto.CryptoUtil;
import civitas.crypto.ElGamalCiphertext;

/**
 * Cache information useful for distributed decryptions. 
 * Information is stored persistently on disk. 
 */
class FileBasedDistDecryptCache implements DistDecryptCache {
    protected final FileBasedElectionCache electionCache;
    protected final String meta;

    FileBasedDistDecryptCache(FileBasedElectionCache cache, String meta, int numBlocks, int numTellers) {
        this.electionCache = cache;
        this.meta = meta==null?"NOMETA":meta;
    }

    private String decryptShareCachename(String meta, int block, int ballotIndex, int tellerIndex) {
        return "decryptShare" +meta+":B"+block+":B"+ballotIndex+"I"+tellerIndex;
    }
    public boolean hasDecryptShare(String meta, int block, int ballotIndex, int tellerIndex) {
        if (!this.meta.equals(meta)) {
            throw new Error("fault: " + this.meta + " not equals " + meta);
        }
        
        String cachename = decryptShareCachename(meta, block, ballotIndex, tellerIndex);
        return electionCache.cachefileExists(cachename);
        
    }
    public TabTellerDistributedDecryptions getDecryptShare(String meta, int block, int ballotIndex, int tellerIndex) {
        if (!this.meta.equals(meta)) {
            throw new Error("fault: " + this.meta + " not equals " + meta);
        }
        
        String cachename = decryptShareCachename(meta, block, ballotIndex, tellerIndex);
        
        // try getting it from file
        BufferedReader reader = this.electionCache.getFileContents(cachename);
        if (reader != null) {
            try {
                TabTellerDistributedDecryptions dd = TabTellerDistributedDecryptions.fromXML(this.electionCache.lbl, reader);
                return dd;
            }
            catch (IllegalArgumentException e) {
                e.printStackTrace();
                this.electionCache.failedCaching(cachename);
            }
            catch (IOException e) {
                e.printStackTrace();
                this.electionCache.failedCaching(cachename);
            }
            finally {
                try {
                    reader.close();
                }
                catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }
    public void setDecryptShare(String meta, int block, int ballotIndex, int tellerIndex, TabTellerDistributedDecryptions d) {
        try {
            if (!this.meta.equals(meta)) {
                throw new Error("fault: " + this.meta + " not equals " + meta);
            }
            if (d != null) {
                String cachename = decryptShareCachename(meta, block, ballotIndex, tellerIndex);
                PrintWriter out = this.electionCache.getFilePrintWriter(cachename);        
                d.toXML(LabelUtil.singleton().noComponents(), out);
                out.close();
            }
        }
        catch (NullPointerException e) { }
        catch (ArrayIndexOutOfBoundsException e) { }        
    }
    private String ciphertextsCachename(String meta, int block, int ballotIndex) {
        return "ciphertexts" +meta+":B"+block+":B"+ballotIndex;
    }
    public void setCiphertexts(String meta, int block, int ballotIndex, Principal TT, Principal SUP, Principal TELLS, ElGamalCiphertext[] ciphertexts) {
        try {
            if (!this.meta.equals(meta)) {
                throw new Error("fault: " + this.meta + " not equals " + meta);
            }
            if (ciphertexts != null) {
                String cachename = ciphertextsCachename(meta, block, ballotIndex);
                PrintWriter fout = this.electionCache.getFilePrintWriter(cachename);
                if (fout != null) {
                    fout.println(ciphertexts.length);
                    for (int i = 0; i < ciphertexts.length; i++) {
                        if (ciphertexts[i] != null) {
                            ciphertexts[i].toXML(LabelUtil.singleton().noComponents(),fout);
                        }
                        else {
                            fout.println("<nullEntry>");
                        }
                    }
                    fout.close();
                    this.electionCache.closedFilePrintStream(cachename);
                }
            }
        }
        catch (NullPointerException e) { }
        catch (ArrayIndexOutOfBoundsException e) { }                
    }
    public ElGamalCiphertext[] getCiphertexts(String meta, int block, int ballotIndex, Principal TT, Principal SUP, Principal TELLS) {
        if (!this.meta.equals(meta)) {
            throw new Error("fault: " + this.meta + " not equals " + meta);
        }
        
        String cachename = ciphertextsCachename(meta, block, ballotIndex);
        
        // try getting it from file
        BufferedReader reader = this.electionCache.getFileContents(cachename);
        if (reader != null) {
            try {
                int length = Integer.parseInt(reader.readLine());
                ElGamalCiphertext[] ciphertexts = new ElGamalCiphertext[length];                   
                for (int i = 0; i < length; i++) {
                    if (Util.isNextTag(this.electionCache.lbl, reader, "nullEntry")) {
                        Util.swallowTag(this.electionCache.lbl, reader, "nullEntry");
                        ciphertexts[i] = null;
                    }
                    else {
                        ciphertexts[i] = CryptoUtil.factory().elGamalCiphertextFromXML(this.electionCache.lbl, reader);
                    }

                }
                return ciphertexts;
            }
            catch (IllegalArgumentException e) {
                e.printStackTrace();
                this.electionCache.failedCaching(cachename);
            }
            catch (IOException e) {
                e.printStackTrace();
                this.electionCache.failedCaching(cachename);
            }
            finally {
                try {
                    reader.close();
                }
                catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }

}