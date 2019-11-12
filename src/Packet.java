import java.io.Serializable;

public class Packet implements Serializable {

    private byte[] encryptedAesShaKey;
    private byte[] encryptedAesKey;
    private byte[] iv;
    private byte[] encryptedAESMessage;
    private String HashMessage;

    public Packet(byte[] encryptedAesShaKey, byte[] encryptedAesKey, byte[] iv, byte[] encryptedAESMessage, String hashMessage) {
        this.encryptedAesShaKey = encryptedAesShaKey;
        this.encryptedAesKey = encryptedAesKey;
        this.iv = iv;
        this.encryptedAESMessage = encryptedAESMessage;
        HashMessage = hashMessage;
    }

    public byte[] getEncryptedAesShaKey() {
        return encryptedAesShaKey;
    }

    public byte[] getEncryptedAesKey() {
        return encryptedAesKey;
    }

    public byte[] getIv() {
        return iv;
    }

    public byte[] getEncryptedAESMessage() {
        return encryptedAESMessage;
    }

    public String getHashMessage() {
        return HashMessage;
    }
}
