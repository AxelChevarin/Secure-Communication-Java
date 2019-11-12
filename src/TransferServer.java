import java.io.*;
import java.net.*;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class TransferServer {



    public static void main(String[] args) throws NoSuchAlgorithmException {
        ServerSocket socket;
        Socket transferSocket;
        try {
            socket = new ServerSocket(2009);
            transferSocket = new Socket("rpiexplorer.io", 8080);
            Thread t = new Thread(new Accepter_clients(socket, transferSocket));
            t.start();
            System.out.println("Mes étudiants sont prêts !");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
class Accepter_clients implements Runnable {
    private ServerSocket socketserver;
    private Socket socket;
    private KeyPair RSAKeyPair;
    private String SHAKey;
    private byte[] encryptedAesShaKey;
    private byte[] encryptedAesKey;
    private byte[] iv;
    private byte[] encryptedAESMessage;
    private KeyPair RSAOttawaKeyPair = GenerateRSAKey();
    private Socket socketTransfer;
    private String HashMessage;

    public Accepter_clients(ServerSocket s, Socket s2) throws NoSuchAlgorithmException {
        socketserver = s;
        socketTransfer = s2;
    }
    public void run() {
        try {
            socket = socketserver.accept();
            Thread t = new Thread(new Accepter_clients(socketserver, socketTransfer ));
            t.start();// Un client se connecte on l'accepte
            PrintWriter out = new PrintWriter(socket.getOutputStream());
            out.println("Bonjour client bienvenue !");
            out.flush();
            RSAKeyPair = GenerateRSAKey();
            String reponse = "";
            SecretKey AESKey;
            String AESKeyString;

            while(!reponse.equals("quit")){

                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                reponse = in.readLine();
                System.out.println(reponse);
                PrintWriter out2 = new PrintWriter(socket.getOutputStream());
                out2.println("Veuillez patienter cryptage en cours ...");
                out2.flush();

                ObjectOutputStream transferCanal = new ObjectOutputStream(socketTransfer.getOutputStream());

                try {
                    AESKey = GenerateAESKey();
                    AESKeyString = Base64.getEncoder().encodeToString(AESKey.getEncoded());
                    SHAKey = SHA512Hashing(AESKeyString);
                    encryptedAesShaKey = encryptionRSAPrivate(RSAKeyPair, SHAKey);
                    encryptedAesKey = encryptionRSAPublic(AESKeyString);
                    iv = generateIV();
                    encryptedAESMessage = encryptionAES256(reponse, AESKey, iv);
                    System.out.println(Base64.getEncoder().encodeToString(encryptedAesKey));
                    out2.println("Cryptage réussi !");
                    out2.flush();
                    out2.println("Debut de l'envoie vers Ottawa ....");
                    out2.flush();


                    HashMessage = SHA512Hashing(reponse);
                    Packet p = new Packet(encryptedAesShaKey,encryptedAesKey,iv,encryptedAESMessage, HashMessage);
                    transferCanal.writeObject(p);
                    transferCanal.flush();

                    out2.println("Message sécurisé envoyé avec succès");



                } catch (Exception e) {
                    e.printStackTrace();
                }
                


            }
            socket.close();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    private KeyPair GenerateRSAKey () throws NoSuchAlgorithmException {


        final int keysize = 1024;

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        keyPairGenerator.initialize(keysize);
        return keyPairGenerator.genKeyPair();
    }

    private SecretKey GenerateAESKey() throws NoSuchAlgorithmException {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey s = keyGen.generateKey();

        return s;

    }

    private byte[] encryptionRSAPrivate (KeyPair keys, String message) throws Exception {

        Cipher ciphermode = Cipher.getInstance("RSA");
        ciphermode.init(Cipher.ENCRYPT_MODE, keys.getPrivate());



        return ciphermode.doFinal(message.getBytes());


    }

    private byte[] encryptionRSAPublic (String decryptedKey) throws Exception {

        Cipher ciphermode = Cipher.getInstance("RSA");

        ciphermode.init(Cipher.ENCRYPT_MODE, RSAOttawaKeyPair.getPublic());


        return ciphermode.doFinal(decryptedKey.getBytes());


    }

    private String SHA512Hashing (String key){

        try {
            MessageDigest md =  MessageDigest.getInstance("SHA-512");
            byte[] byteSHA = md.digest(key.getBytes());
            String SHA = Base64.getEncoder().encodeToString(byteSHA);
            return SHA;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }


    }

    private byte[] encryptionAES256 (String message, SecretKey key, byte[] iv){

        int iteration = 10000;
        int keySize = 256;
        byte [] encryptedMessage = null;

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);
            encryptedMessage = cipher.doFinal(message.getBytes());



        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }


        return encryptedMessage;
    }

    private byte[] generateIV(){
        byte[] iv;
        SecureRandom secRandom = null;
        try {
            secRandom = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        iv = new byte[128/8];
        secRandom.nextBytes(iv);

        return  iv;

    }


}


