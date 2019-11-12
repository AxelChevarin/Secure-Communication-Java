import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class SenderClient {

    public static void main(String[] zero){
        Socket socket;
        try {
            socket = new Socket("localhost",8080);
            BufferedReader in = new BufferedReader (new InputStreamReader(socket.getInputStream()));
            String message_distant = in.readLine();
            System.out.println("Serveur : " + message_distant);
            System.out.println("Ecrire quit pour arrêter la conversation");
            Scanner sc = new Scanner(System.in);
            System.out.println("Votre réponse : ");
            String sendMessage = "";
            PrintWriter out = new PrintWriter(socket.getOutputStream());
            while (!sendMessage.equals("quit")){

                sendMessage = sc.nextLine();
                out.println(sendMessage);
                out.flush();
                System.out.println(in.readLine());
                System.out.println(in.readLine());

            }

            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
