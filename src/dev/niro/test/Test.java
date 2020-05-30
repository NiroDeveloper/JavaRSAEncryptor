package dev.niro.test;

import java.io.File;

import dev.niro.rsacryptor.RSAEncryptor;

public class Test {

	public static void main(String[] args) throws Exception {   
		System.out.println("Creating Key...");
		RSAEncryptor rsac = new RSAEncryptor(RSAEncryptor.createNewKeyPair(4096));
		System.out.println("Generated Key!");		
		
		System.out.println("String en-/decryption test...");
		String startString = "This is a test encryption!";
		byte[] startBytes = startString.getBytes();
		byte[] encryptedBytes = rsac.encrypt(startBytes);
		System.out.println("Encrypted: " + new String(encryptedBytes));
		byte[] decryptedBytes = rsac.decrypt(encryptedBytes);
		String decryptedString = new String(decryptedBytes);
    	System.out.println("Decrypted: " + decryptedString);
    	System.out.println("String en-/decryption tested!");
    	
    	File input = new File(System.getProperty("user.home") + "/Desktop/video.mp4");
    	File encFile = new File(input.getAbsolutePath() + "_enc");
    	System.out.println("Encrypting File...");
    	rsac.encryptFile(input, encFile);
    	System.out.println("Encrypted File! Decrypting File...");
    	rsac.decryptFile(encFile, new File(input.getParent() + "/dec_" + input.getName()));
    	System.out.println("Decrypted File!");
    }
	
}
