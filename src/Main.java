public class Main {

    public static void main(String[] args) {
	// write your code here
        AES aes = AES.init("hello world", "ciphering", true);
        String encryptedMessage = (aes.encrypt());

        AES decryptAes = AES.init(encryptedMessage.replaceAll(" ", ""), "ciphering", true);
        String decryptedMessage = decryptAes.decrypt();
    }


}
