//Anurag Vij
//2019212

import java.util.*; 
import java.io.*;  
import java.net.*;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

//this is the client file made in java and connected through server using socket programming

public class client {  

    static int key0;
    static int key1;
    static int key2;
    static int sn1;
    static int sn2;
    static String columnaftermixing;
    static String roundkey1;
    static String roundkey2;
    static String shiftroword1;
    static String shiftrow2;

    //SubstituteNibble function used in key generation
    static int SubstituteNibble(int n, int[][] sb)
    {
        int s1 = (n%2) + ((n/2)%2)*2 + ((n/4)%2)*4 +((n/8)%2)*8;
        int s2 = (n-s1)/16;
        s1=sb[s1][1];
        s2=sb[s2][1];
        return s1*16+s2;
    }

    //key scheduling algorithm
    static int[] key_gen(int n , int[][] sb)
    {
        int[] key =new int[16];
        DectoBin(n, key);
        int[] roundkey = new int[3];
        int word0 = 128*key[0]+64*key[1]+32*key[2]+16*key[3]+8*key[4]+4*key[5]+2*key[6]+key[7];
        int word1 = 128*key[8]+64*key[9]+32*key[10]+16*key[11]+8*key[12]+4*key[13]+2*key[14]+key[15];
        int word2 = word0^128^SubstituteNibble(word1, sb);
        int word3 = word2^word1;
        int word4 = word2^48^SubstituteNibble(word3, sb);
        int word5 = word4^word3;

        sn1=SubstituteNibble(word1, sb);
        sn2=SubstituteNibble(word3, sb);
        roundkey[0]=n;
        roundkey[1]=word2*256 + word3;
        roundkey[2]=word4*256+word5;

        return roundkey;

    }


   // Function to  convert decimal to binary 
    static void DectoBin(int n , int[] a )
    {   
        for (int i =15; i >= 0; i--) { 
            int k = n >> i; 
            if ((k & 1) > 0) 
                a[15-i]=1; 
            else
                a[15-i]=0; 
        } 
   }

   //Function to initialize the state matrix
   static int[][] m(int [] y)
   {
    int[][] present =new int[2][2];
    present[0][0]=(8*y[0]+4*y[1]+2*y[2]+y[3]);
    present[1][0]=(8*y[4]+4*y[5]+2*y[6]+y[7]);
    present[0][1]=(8*y[8]+4*y[9]+2*y[10]+y[11]);
    present[1][1]=(8*y[12]+4*y[13]+2*y[14]+y[15]);

    return present;
   }
    //function to implement AES AES_Encryption
    static String AES_Encryption(int a , int b , int key)
    {    

         //defining S-box
         int[][] sb = {{0,9},{1,4},{2,10},{3,11},{4,13},{5,1},{6,8},{7,5},{8,6},{9,2},{10,0},{11,3},{12,12},{13,14},{14,15},{15,7}};

         //For storing key generated for 2 round
         int [] key_aay = new int[3];
         key_aay =key_gen(key, sb);

         key0=key_aay[0];
         key1=key_aay[1];
         key2=key_aay[2];

         //defining aay for storing binary number
         int[] plaintext = new int[16];

         //lookup table for mix column
         int [][] Mix_column ={
                      {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
                      {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
                      {0,2,4,6,8,10,12,14,3,1,7,5,11,9,15,13},
                      {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
                      {0,4,8,12,3,7,11,15,6,2,14,10,5,1,13,9},
                      {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
                      {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
                      {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
                      {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
                      {9,1,8,2,11,3,10,4,13,5,12,6,15,7,14}};
       
         //Function to convert the decimal no. to binary
         DectoBin((a*256+b)^key_aay[0], plaintext); 
      
         //defining present m as 2D aay
         int[][] present =new int[2][2];
         present=m(plaintext);

        //Variable for Storing Ct 
        String ct=null;

        for(int h=1;h<=2;h++)
       {
        //S-box operation
        present[0][0]=sb[present[0][0]][1];
        present[0][1]=sb[present[0][1]][1];
        present[1][0]=sb[present[1][0]][1];
        present[1][1]=sb[present[1][1]][1];

         //Shift row operation
         int temp;
         temp=present[1][0];
         present[1][0]=present[1][1];
         present[1][1]=temp;

         String s="";

        //  System.out.format("Shift row %d:",h);        
         s=s+String.format("%04d", Long.parseLong(Integer.toBinaryString(present[0][0])));
         s=s+String.format("%04d", Long.parseLong(Integer.toBinaryString(present[0][1])));
         s=s+String.format("%04d", Long.parseLong(Integer.toBinaryString(present[1][0])));
         s=s+String.format("%04d", Long.parseLong(Integer.toBinaryString(present[1][1])));
        //  System.out.println(s);
         
         if(h==1){
             shiftroword1 = s;
         }
         else if(h==2){
             shiftrow2 = s;
         }

         //Used for mixing the columns
        if(h==1)
         {
             
		int s1=present[0][0],s2=present[1][0],s3=present[0][1],s4=present[1][1];
		present[0][0]=s1^Mix_column[4][s2];
		present[1][0]=Mix_column[4][s1]^s2;
		present[0][1]=s3^Mix_column[4][s4];
		present[1][1]=Mix_column[4][s3]^s4;

        columnaftermixing=Integer.toBinaryString(present[0][0]) + Integer.toBinaryString(present[1][0]) + Integer.toBinaryString(present[0][1]) + Integer.toBinaryString(present[1][1]);
         }
        
        // For storing key in binary form
        int[] op= new int[16];
        DectoBin(key_aay[h],op);

        //For storing key in present matix
        int[][] output_matrix = m(op);

        //Performing XOR operation with Round key to get round key
        

        String str="";
        for(int i=0;i<2;i++){
            
         for(int j=0;j<2;j++)
          {
            present[i][j]=present[i][j]^output_matrix[i][j];
            str=str+String.format("%04d", Long.parseLong(Integer.toBinaryString(present[i][j])));
          }

        }
        if(h==1){
            roundkey1=str;
        }
        else if(h==2){
            roundkey2=str;
        }
        
       }
       //Converting CipherText bit into character
       char alphabet_1= (char)(present[0][0]*16 + present[1][0]);
       char alphabet_2= (char)(present[0][1]*16 + present[1][1]);
       
       //joining two character as String
        ct= String.valueOf(alphabet_1) + String.valueOf(alphabet_2);
       return ct;

    }

    //function to create digest of a message to use in rsa encryption
    public static BigInteger getMd5(String input)
    {
        try{
            // Static getInstance method is called with hashing MD5
                MessageDigest md = MessageDigest.getInstance("MD5");
  
            // digest() method is called to calculate message digest
            //  of an input digest() return aay of byte
                byte[] messageDigest = md.digest(input.getBytes());
  
            // Convert byte array into signum representation
                BigInteger no = new BigInteger(1, messageDigest);
  
            
            return no;
        }

        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    //function to find gcd of two numbers
    static int gcd(int a, int b)
    {
        if (a == 0)
            return b;
        return gcd(b % a, a);
    }
 
    // A simple method to evaluate
    // Euler Totient Function
    static int pi(int n)
    {
        int result = 1;
        for (int i = 2; i < n; i++)
            if (gcd(i, n) == 1)
                result++;
        return result;
    }
  
    
    public static int inverse(int r1 , int r2)
    {   int t1=0,t2=1;
        while (r2>0)
        {
            int q=r1/r2;
            int r=r1-q*r2;
            r1=r2;
            r2=r;
            int  t=t1-q*t2;
            t1=t2;
            t2=t;

        }
        return t1;
    }

    public static BigInteger RSAEncryption(int m, int e , int n)
    {

        BigInteger message = BigInteger.valueOf(m);
        BigInteger exponent = BigInteger.valueOf(e);
        BigInteger div = BigInteger.valueOf(n);

        return message.modPow(exponent, div);

    }

    public static BigInteger RSA_Digital_Signature(String message , int d , int n)
    {
        BigInteger digest = getMd5(message);
        return digest.modPow(BigInteger.valueOf(d), BigInteger.valueOf(n));
        
    }

 //MAIN SECTION     
    
public static void main(String[] args) {  
try{      
    Socket s=new Socket("localhost",6666);   
    DataInputStream dis=new DataInputStream(s.getInputStream());
    OutputStream outputStream = s.getOutputStream();
    ObjectOutputStream object = new ObjectOutputStream(outputStream);
    
    //Recieving message from sender
    Scanner sc= new Scanner(System.in); 
    System.out.print("Enter message : ");
    String m= sc.nextLine();
    
    String message="";

    //Adding a bit to make code compatible 
    if(m.length()%2!=0)
      message=m+" ";
    else message=m;

    //Initializing key and sending over sockets
    System.out.print("Key : ");
    int key =sc.nextInt();
    
    //generating key for client in rsa
    System.out.println("Enter public key parameters");
    System.out.print("p: ");
    int p= sc.nextInt();
    System.out.print("q: ");
    int q= sc.nextInt();
    System.out.print("e: ");
    int e= sc.nextInt();

    int  n ;
    int  pi;
    int d ;

    //Getting server public key
    int s_n = dis.readInt();
    int s_e = dis.readInt();

    n=p*q;
    pi = pi(n);

    d=inverse(pi, e);

    //AES_Encryption starts..
     char[] ch = message.toCharArray();                           
     String CipherText="";
     for(int i=0;i<ch.length - 1;i+=2)
    {  
       //Converting bits into two character
       int x= ch[i] ;
       int y=ch[i+1];

       // Concatening all Encrypting bit 
       CipherText=CipherText.concat(AES_Encryption(x, y, key));
    }

    //Encrypting SecretKey
    BigInteger secretkey = RSAEncryption(key, s_e, s_n);

    //Creating Client signature
    BigInteger sign = RSA_Digital_Signature(message, d, n);

    

    //Sending ciphertext over socket to server

    Send_msg obj = new Send_msg(CipherText,secretkey,sign,n,e);
       object.writeObject(obj);  
       s.close();

    //Output to be printed
    System.out.println("Encrypted Secret Key : " + secretkey);
    System.out.println("After Pre-round transformation:");
    System.out.println("Round Key K0: "+String.format("%016d", Long.parseLong(Integer.toBinaryString(key0))));
    System.out.println("After Round 1 Substitute nibbles: "+String.format("%016d", Long.parseLong(Integer.toBinaryString(sn1))));
    System.out.println("After Round 1 Shift rows: "+shiftroword1);
    System.out.println("After Round 1 Mix columns: "+String.format("%016d", Long.parseLong(columnaftermixing)));
    System.out.println("After Round 1 Add round key: "+roundkey1);

    System.out.println("Round Key K1: "+String.format("%016d", Long.parseLong(Integer.toBinaryString(key1))));
    System.out.println("After Round 2 Substitute nibbles: "+String.format("%016d", Long.parseLong(Integer.toBinaryString(sn2))));
    System.out.println("After Round 2 Shift rows: "+shiftrow2);
    System.out.println("After Round 2 Add round key: "+roundkey2);
    System.out.println("Round Key K2: "+String.format("%016d", Long.parseLong(Integer.toBinaryString(key2))));

    System.out.println("Cipher text :" + CipherText);
    System.out.println("Digest :" + getMd5(message));
    System.out.println("Digital Signature :" + sign);
}catch(Exception e){System.out.println(e);}  
}  
}
class Send_msg implements Serializable {
    
    private static final long serialVersionUID = 1L;
    public String Ct;
    public BigInteger secretkey;
    public BigInteger sign;
    public int clientpublickey;
    public int clientpublickey_e;
 
     public Send_msg(String Ct, BigInteger secretkey, BigInteger sign,int clientpublickey, int clientpublickey_e)
     {
         this.Ct=Ct;
         this.secretkey=secretkey;
         this.sign=sign;
         this.clientpublickey=clientpublickey;
         this.clientpublickey_e=clientpublickey_e;
     }
 
 }