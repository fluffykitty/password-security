import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
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
 */

public class Shell {

    static String sh = ">> ";

    static Map<String,String> usernameAndPassword = new HashMap<String,String>();
    static Map<String,String> usernameAndSalt = new HashMap<String,String>();
    static File PASSWORD_FILE = new File("password.txt");

    static boolean LOGGEDIN = false;

    public static void main(String [] args) throws Exception {

        int status;
        String input;
        Scanner sc = new Scanner(System.in);

        System.out.println("\n--------------------------------------------");
        System.out.println("------------- ROSTAM PANJSHIRI -------------");
        System.out.println("------------- VCU SPRING 2018  -------------");
        System.out.println("------------- CMSC  413  FUNG  -------------");
        System.out.println("------------- ASSIGNMENT FIVE  -------------");
        System.out.println("--------------------------------------------\n");

        System.out.println(sh + "Welcome to the shell!");
        System.out.println(sh + "Type 'help' to see available commands.");
        importUsers();

        shell: while(true){
            System.out.print(sh);
            input = sc.next();

            status = handleCmd(input);
            switch(status){
                case -1:
                    System.out.println(sh + "terminating console...\n");
                    break shell;
                case 0:
                    System.out.println(sh + "Unrecognized command: " + input + "\n");
                    continue shell;
                case 1:
                    System.out.println("Commands within the shell are:");
                    System.out.println("    - create-login");
                    System.out.println("    - login");
                    System.out.println("    - logout");
                    System.out.println("    - help");
                    System.out.println("    - reload");
                    System.out.println("    - exit\n");
                    continue shell;
                case 2:
                    //do logout here
                    logout();
                    System.out.println();
                    continue shell;
                case 3:
                    //do login here
                    login();
                    System.out.println();
                    continue shell;
                case 4:
                    //do create-login here
                    createLogin();
                    System.out.println();
                    continue shell;
                case 5:
                    //do reload
                    importUsers();
                    System.out.println("Reloaded current users from passwords.txt\n");
                    continue shell;
                default:
                    System.out.println(sh);
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

        //prompt user
        System.out.print(sh+"Username:");
        user = sc.next();
        System.out.print(sh+"Password:");
        pass = sc.next();

        if (isNullOrBlank(user) || isNullOrBlank(pass)){
            System.out.println(sh+"Please enter a username/password.");
            return;
        }

        //validating
        if(usernameAndPassword.containsKey(user)){

            //passing in the input password and the salt from that user
            boolean valid = verifyPassword(pass, usernameAndPassword.get(user), usernameAndSalt.get(user));

            if(valid){
                System.out.println(sh+"Login success.");
                sh = user + "@home >> ";
                LOGGEDIN = true;
            }
            else {
                System.out.println(sh+"Invalid login.");
            }
        }
        else {
            System.out.println(sh+"Username, huh?");
        }

    }

    static void logout(){
        if(LOGGEDIN){
            LOGGEDIN = false;
            sh = ">> ";
            System.out.println(sh+"Logged out successfully.");
        } else {
            System.out.println(sh+"You are not logged in.");
        }
    }

    static void createLogin() throws Exception{
        Scanner sc = new Scanner(System.in);
        String user = "";
        String pass = "";

        //prompt user
        System.out.print(sh+"Enter a Username:");
        user = sc.next().trim();
        System.out.print(sh+"Enter a Password:");
        pass = sc.next();

        if (isNullOrBlank(user) || isNullOrBlank(pass)){
            System.out.println(sh+"Please enter a username/password.");
            return;
        } else if (usernameAndPassword.containsKey(user)){
            System.out.println(sh+"Username already exists.");
            return;
        } else if (!isSecure(pass)){
            System.out.println(sh+"Password is not strong enough. " +
                    "Password must contain at least 8 characters, " +
                    "letters, numbers, a special character, and " +
                    "cannot have three consecutive characters.");
            return;
        }

        //hash password NEEDS TO BE DONE IN CREATE
        String resp = hashPassword(pass);
        String h_pass = resp.split("\\s+")[0];
        String h_salt = resp.split("\\s+")[1];

        //writes hash of pass and salt to password file
        PrintWriter writer = new PrintWriter(new FileWriter(PASSWORD_FILE, true));
        writer.println(user + " " + h_pass + " " + h_salt);
        writer.close();

        System.out.println(sh+"Username and Password created.");
        importUsers();
    }

    static void importUsers() throws Exception{
        BufferedReader br = new BufferedReader(new FileReader(PASSWORD_FILE));
        String nextLine = "";
        while( (nextLine = br.readLine()) != null && nextLine.length()!=0){
            String[] line = nextLine.split(" ");
            String user = line[0];
            String pass = line[1];
            String salt = line[2];

            usernameAndPassword.put(user, pass);
            usernameAndSalt.put(user, salt);
        }
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

        //System.out.printf("salt: %s%n", enc.encodeToString(salt));
        //System.out.printf("hash: %s%n", enc.encodeToString(hash));

        //return hash and salt to store
        return enc.encodeToString(hash) + " " + enc.encodeToString(salt);
    }

    static Boolean verifyPassword(String input_pass, String hash, String salt) throws Exception{
        Base64.Decoder dec = Base64.getDecoder();
        byte[] decodedSalt = dec.decode(salt);

        //create hash
        KeySpec spec = new PBEKeySpec(input_pass.toCharArray(), decodedSalt, 65536, 128);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] h_input_pass = f.generateSecret(spec).getEncoded();

        Base64.Encoder enc = Base64.getEncoder();
        //System.out.printf("h_input_pass: %s%n", enc.encodeToString(h_input_pass));

        //compare passwords
        return (enc.encodeToString(h_input_pass).equals(hash));
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
        if (s.equalsIgnoreCase("exit"))
            return -1;
        else if (s.equalsIgnoreCase("help"))
            return 1;
        else if (s.equalsIgnoreCase("logout"))
            return 2;
        else if (s.equalsIgnoreCase("login"))
            return 3;
        else if (s.equalsIgnoreCase("create-login"))
            return 4;
        else if (s.equalsIgnoreCase("reload"))
            return 5;

        return 0;
    }

    static boolean isSecure(String pass){

        //checks for letter, number, special character, and length >= 8
        String regex = "(?=.*[!@#\\$\\%\\^\\&\\*\\(\\)\\\\\\[\\]\\?])(?=.*[a-zA-Z])(?=.*[0-9]).{8,}";
        if (!pass.matches(regex))
            return false;

        //checking for 3 consecutive letters or numbers
        char[] asc = pass.toCharArray();
        int counter = 1;
        int prev = 0;
        for(int i = 0; i < asc.length; i++){
            if ((int)asc[i] == prev + 1){
                counter++;
            } else {
                counter = 1;
            }
            prev = asc[i];
            if(counter == 3)
                return false;
        }

        //checking for 3 consecutive special characters
        if(pass.contains("!@#") || pass.contains("@#$") || pass.contains("#$%") ||
                pass.contains("$%^") || pass.contains("%^&") || pass.contains("^&*") ||
                pass.contains("&*(") || pass.contains("*()") || pass.contains("()_") ||
                pass.contains(")_+"))
            return false;

        return true;

    }//isSecure

}
