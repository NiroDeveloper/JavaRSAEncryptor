package dev.niro.rsacryptor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;

public class RSAEncryptor {
	
	private KeyPair keyPair;
	private int bufferSize = -1;
	private int outputBufferSize = -1;
	
	protected int threadAmount = (int) (Runtime.getRuntime().availableProcessors() * 1.25);
	
	private static final String CRYPTION = "RSA";
	
	public RSAEncryptor(int keyLength) {
		setKeyPair(createNewKeyPair(keyLength));
	}
	
	public RSAEncryptor(KeyPair keyPair) {
		setKeyPair(keyPair);
	}
	
	public void setKeyPair(KeyPair keyPair) {
		int keyLength = ((RSAPublicKey)keyPair.getPublic()).getModulus().bitLength();
		this.keyPair = keyPair;	
		bufferSize = keyLength / 8 - 11;
		outputBufferSize = (int) Math.ceil(keyLength / 8.0);
	}
	
	public static KeyPair createNewKeyPair(int keyLength) {
		KeyPairGenerator keyGen = null;
		try {
			keyGen = KeyPairGenerator.getInstance(CRYPTION);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
    	keyGen.initialize(keyLength);
    	return keyGen.generateKeyPair();
	}
	
	public static KeyPair createKeyPair(byte[] publicKey, byte[] privateKey) throws InvalidKeySpecException {
	    KeyFactory kf = null;
		try {
			kf = KeyFactory.getInstance(CRYPTION);
			return new KeyPair(kf.generatePublic(new X509EncodedKeySpec(publicKey)), 
					kf.generatePrivate(new PKCS8EncodedKeySpec(privateKey)));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static KeyPair createKeyPair(byte[] publicKey) throws InvalidKeySpecException {
	    KeyFactory kf = null;
		try {
			kf = KeyFactory.getInstance(CRYPTION);
			return new KeyPair(kf.generatePublic(new X509EncodedKeySpec(publicKey)), null);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
		 
    public byte[] encrypt(byte[] data) {
    	ExecutorService es = Executors.newFixedThreadPool(threadAmount);
    	
    	byte[] out = new byte[(int) (outputBufferSize * Math.ceil((double)data.length / bufferSize))];
		
		for(int t = 0; t <= data.length; t += bufferSize) {    
			final int i = t;
			es.execute(new Runnable() {				
				@Override
				public void run() {
					int bytesNow = data.length - i;
		    		int packageSize = bytesNow < bufferSize ? bytesNow : bufferSize;
		    		if(packageSize <= 0)
		    			return;
		    		byte[] b = new byte[packageSize];
		    		for(int l = 0; l < packageSize; l++)
		    			b[l] = data[i + l];    		
		    		try {
		    			Cipher cipher = Cipher.getInstance(CRYPTION);
		    	    	cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
						b = cipher.doFinal(b);
					} catch (Exception e) {
						e.printStackTrace();
					}
		    		for(int l = 0; l < outputBufferSize; l++)
		    			out[(int) ((double)i / bufferSize * outputBufferSize + l)] = b[l];
				}
			});
    	}
				
    	es.shutdown();
    	try {
			es.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
    	return out;
	}

	public byte[] decrypt(byte[] data) {
		ExecutorService es = Executors.newFixedThreadPool(threadAmount);
		
		byte[] out = new byte[data.length / outputBufferSize * bufferSize]; 
		final IntegerCoat shortOut = new IntegerCoat();
		
    	for(int t = 0; t < data.length; t += outputBufferSize) {  
    		final int i = t;
    		es.execute(new Runnable() {				
				@Override
				public void run() {
					byte[] input = new byte[outputBufferSize];
		    		for(int l = 0; l < outputBufferSize; l++)
		    			input[l] = data[i + l];
		    		
					try {
						Cipher cipher = Cipher.getInstance(CRYPTION);
						cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());		
						byte[] result = cipher.doFinal(input);
						shortOut.integer += bufferSize - result.length;
						
						for(int l = 0; l < result.length; l++)
			    			out[i / outputBufferSize * bufferSize + l] = result[l];
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			});
    	}
    	
    	es.shutdown();
    	try {
			es.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
    	return shortOut.integer != 0 ? Arrays.copyOf(out, out.length - shortOut.integer) : out;
	}
	
	public void encryptStream(InputStream is, OutputStream os) throws IOException {
		byte[] buffer = new byte[bufferSize];
		while(is.read(buffer) != -1)
			os.write(encrypt(buffer));
	}
	
	public void decryptStream(InputStream is, OutputStream os) throws IOException {
		byte[] buffer = new byte[outputBufferSize];
		while(is.read(buffer) != -1)
			os.write(decrypt(buffer));
	}
		
	public void encryptFile(File input, File output) throws IOException {
		FileInputStream fis = new FileInputStream(input);
		FileOutputStream fos = new FileOutputStream(output);
		byte[] data = new byte[(int)input.length()];
		fis.read(data);
		fos.write(encrypt(data));
		fis.close();
		fos.close();
	}
	
	public void decryptFile(File input, File output) throws IOException  {
		FileInputStream fis = new FileInputStream(input);
		FileOutputStream fos = new FileOutputStream(output);
		byte[] data = new byte[(int)input.length()];
		fis.read(data);
		fos.write(decrypt(data));
		fis.close();
		fos.close();
	}
	
	public int getThreadAmount() {
		return threadAmount;
	}

	public void setThreadAmount(int threadAmount) {
		this.threadAmount = threadAmount;
	}

	public KeyPair getKeyPair() {
		return keyPair;
	}
	
	public byte[] getPublicKeyEncoded() {
		return keyPair.getPublic().getEncoded();
	}
	
	public byte[] getPrivateKeyEncoded() {
		return keyPair.getPrivate().getEncoded();
	}
}

class IntegerCoat {
	public int integer = 0;
}
