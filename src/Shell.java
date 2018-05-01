import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.*;

/**
 *
 * Rostam Panjshiri
 * VCU Spring 2018
 * CMSC 413
 * Dr. Carol Fung
 * Assignment 5
 *
 *
 */

public class Shell {

    static String sh = ">>: ";
    static Map<String,String> usernameAndPassword = new HashMap<String,String>();
    static Map<String,String> usernameAndSalt = new HashMap<String,String>();
    static boolean loggedIn = false;

    public static void main(String [] args) throws Exception {

        int status;
        String input;
        Scanner sc = new Scanner(System.in);

        System.out.println(sh + "Welcome to the shell!");

        shell: while(true){
            System.out.print(sh);
            input = sc.next();

            status = handleCmd(input);
            switch(status){
                case -1:
                    System.out.println(sh + "terminating console...");
                    break shell;
                case 0:
                    System.out.println(sh + "Unrecognized command: " + input);
                    continue shell;
                case 1:
                    System.out.println("Commands within the shell are:");
                    System.out.println("    - create-login");
                    System.out.println("    - login");
                    System.out.println("    - logout");
                    System.out.println("    - help");
                    System.out.println("    - exit");
                    continue shell;
                case 2:
                    //do logout here
                    logout();
                    continue shell;
                case 3:
                    //do login here
                    login();
                    continue shell;
                case 4:
                    //do create-login here
                    continue shell;
                default:
                    continue shell;
            }//switch

        }//while

    }//driver

    /**
     * ***********************************************************************************************
     * PROGRAM FUNCTIONS
     * ***********************************************************************************************
     */

    static void login() throws Exception{
        Scanner sc = new Scanner(System.in);
        String user = "";
        String pass = "";

        System.out.print(sh+"Username:");
        user = sc.next();
        System.out.print(sh+"Password:");
        pass = sc.next();

        if (isNullOrBlank(user) || isNullOrBlank(pass)){
            System.out.println(sh+"Please enter a username/password.");
            return;
        }

        String resp = hashPassword(pass);
        String hp = resp.split("\\s+")[0];
        String h_salt = resp.split("\\s+")[1];
        boolean f = verifyPassword(pass, h_salt);

        //validating
        if(usernameAndPassword.containsKey(user)){

            if(pass.equals(usernameAndPassword.get(user))){
                System.out.println(sh+"Login success.");
                sh = user + ">>: ";
                loggedIn = true;
            }
            else {
                System.out.println(sh+"Invalid login.");
            }
        }

    }

    static void logout(){
        if(loggedIn){
            loggedIn = false;
            sh = ">>:";
            System.out.println(sh+"Logged out successfully.");
        }
        System.out.println(sh+"You are not logged in.");
    }

    /**
     * ***********************************************************************************************
     * CRYPTOGRAPHY FUNCTIONS
     * ***********************************************************************************************
     */

    static String hashPassword(String pass) throws Exception{
        //updating salt
        Random rand = new Random();
        byte[] salt = new byte[16];
        rand.nextBytes(salt);

        //create hash
        KeySpec spec = new PBEKeySpec(pass.toCharArray(), salt, 65536, 128);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1"); //can use sha512 also
        byte[] hash = f.generateSecret(spec).getEncoded();

        //encode in base64 to store in text file
        Base64.Encoder enc = Base64.getEncoder();
        System.out.printf("salt: %s%n", enc.encodeToString(salt));
        System.out.printf("hash: %s%n", enc.encodeToString(hash));

        //return hash and salt to store
        return enc.encodeToString(hash) + " " + enc.encodeToString(salt);
    }

    static Boolean verifyPassword(String pass, String salt) throws Exception{
        Base64.Decoder dec = Base64.getDecoder();
        byte[] decryptedSalt = dec.decode(salt);
        byte[] decryptedPass = dec.decode(pass);

        //create hash
        KeySpec spec = new PBEKeySpec(pass.toCharArray(), decryptedSalt, 65536, 128);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1"); //can use sha512 also
        byte[] hash = f.generateSecret(spec).getEncoded();

        Base64.Encoder enc = Base64.getEncoder();
        System.out.printf("pass: %s%n", pass);
        System.out.printf("hash: %s%n", enc.encodeToString(hash));

        //compare passwords
        return (hash.equals(decryptedSalt));
    }


    /**
     * ***********************************************************************************************
     * UTILITY FUNCTIONS
     * ***********************************************************************************************
     */
    static boolean isNullOrBlank(String s)
    {
        return (s==null || s.trim().equals(""));
    }

    static int handleCmd(String s){
        if (s.equals("exit"))
            return -1;
        else if (s.equals("help"))
            return 1;
        else if (s.equals("logout"))
            return 2;
        else if (s.equals("login"))
            return 3;
        else if (s.equals("create-login"))
            return 4;

        return 0;
    }

}
