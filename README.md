# Java RSA Encryptor - Multithreading - Easy to use
Easily encrypt and decrypt data, like Strings or Files. Library is multithreading.

## Create KeyPair - Public and Private Key
```
// parameter is the key bit length
KeyPair kp = RSAEncryptor.createNewKeyPair(4096);

// or create from existing keys
KeyPair kp = RSAEncryptor.createKeyPair(publicKey, privateKey);
// if you only have the public key - decryption will not work
KeyPair kp = RSAEncryptor.createKeyPair(publicKey);
```
## Create RSAEncryptor-Object
```
// kp is a KeyPair-Object
RSAEncryptor rsac = new RSAEncryptor(kp);

// or create an RSAEncryptor-Object with an new KeyPair
// parameter is the key bit length
RSAEncryptor rsac = new RSAEncryptor(2048);
```

## Encrypt / Decrypt Bytearray
```
// Some bytes to encrypt
byte[] startBytes = new byte[] {1, 2, 3, 4, 5};

// Encrypt by public key in KeyPair
byte[] encryptedBytes = rsac.encrypt(startBytes);

// Decrypt by private key in KeyPair
byte[] decryptedBytes = rsac.decrypt(encryptedBytes);
```

## Encrypt / Decrypt String
```
String startString = "This is a test encryption!";
byte[] startBytes = startString.getBytes();

// Encrypt String by public key
byte[] encryptedBytes = rsac.encrypt(startBytes);
System.out.println("Encrypted: " + new String(encryptedBytes));

// Decrypt String by private key
byte[] decryptedBytes = rsac.decrypt(encryptedBytes);
String decryptedString = new String(decryptedBytes);
System.out.println("Decrypted: " + decryptedString);
```

## Encrypt / Decrypt File
```
File input = new File(System.getProperty("user.home") + "/Desktop/video.mp4");
File encFile = new File(input.getAbsolutePath() + "_enc");

// Encrypt File by public key
rsac.encryptFile(input, encFile);

// Decrypt File by private key
rsac.decryptFile(encFile, new File(input.getParent() + "/dec_" + input.getName()));
```

## Change Thread Amount
```
// Default:
// threadAmount = (int) (Runtime.getRuntime().availableProcessors() * 1.25)

// Get amount
int oldAmount = rsac.getThreadAmount();
// Set amount
rsac.setThreadAmount(4);
```

## Get Keys for example to transfer them and load them
```
byte[] publicKey = rsac.getPublicKeyEncoded();
byte[] privateKey = rsac.getPrivateKeyEncoded();

// And load them into an key pair
KeyPair kp = RSAEncryptor.createKeyPair(publicKey, privateKey);
// if you only have the public key - decryption will not work
KeyPair kp = RSAEncryptor.createKeyPair(publicKey);
```

## Encrypt / Decrypt Stream - Without multithreading
```
FileInputStream fis = new FileInputStream(input);
FileOutputStream fos = new FileOutputStream(output);
rsac.encryptStream(fis, fos);
// rsac.decryptStream(fis, fos);
fis.close();
fos.close();
```

## Change Keypair from RSAEncryptor-Object - Optimally don't use it
```
rsac.setKeyPair(keyPair);
```
