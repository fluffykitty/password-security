# PASSWORD-SECURITY

Sample program designed as a console / shell to allow users to "login", "create-login", and "logout".

#### Usage

To compile and run, download the src directory or the A5-RP folder.
It is not designed to take STD INPUT, thus you must ensure that the "passwords.txt" file is located within the same directory.
- `javac Shell.java` to compile
- `java Shell` to execute the program

Again, ensure that the Java Runtime Environment (JRE) is installed and the PATH variable is set if needed to compile (on Windows).
Also again, ensure that a "passwords.txt" text file exists in the active directory. It is what is used to store user log-in info. 

#### Commands
- `exit` exits the console
- `help` shows available commands whilst running
- `create-login` gives you the option to enter a username + password
- `login` allows you the chance to log in, if you know a valid username + passwd combo
- `logout` logs you out of the console
- `reload` refreshes the list of usernames and passwords stored in *password.txt*. Needed if file is externally updated

### Internals
The shell is intentionally simple as this is an exhibition of only password security.
The password encryption algorithm used is **PBKDF2WithHmacSHA1**. 

Password-based-Key-Derivative-Function 2 (PBKDF2) with Keyed-Hash Message Authentication Code (HMAC) and SHA1.
SHA1 (160bits) can easily be substituted with SHA256 or SHA512 for tougher hashes. Salts are randomly generated.

This reinforces the password.txt directory from dictionary attacks, brute force attacks, rainbow table attacks, and so on.

#### Credit
> Written for Dr.Carol Fung's Cybersecurity (CMSC 413) at Virginia Commonwealth University in Spring 2018.
> Written By me, Rostam Panjshiri.
