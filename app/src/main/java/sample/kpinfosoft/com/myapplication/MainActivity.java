package sample.kpinfosoft.com.myapplication;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    private static final SecureRandom random = new SecureRandom();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        String key = "PBKDF2WithHmacSHA1"; // 128 bit key
        String initVector = "2"; // 16 bytes IV

//        encrypt(key, initVector, "Hello World");
//        encrypt(key, initVector, "Hello World");

//        decrypt(key, initVector, encrypt(key, initVector, "Hello World"));

//        System.out.println(decrypt(key, initVector, encrypt(key, initVector, "Hello World")));

        Log.d("convertURL ", convertURL("vwskjKmX9GyCjZ/rHObpMjnP1fWg7Jl4mrpUHfoOVCI=]9odXy6BgpjlOhb92Devheg==]0XhKOLbgz8B4EpGx0qBb6VBUPK3i8uYk6KV3tIfm7gaXP28i4mpxPPKktFriUKqSQiFpHVX8PhjCu0YUtKZr+dm/W7Shfxa3DisAf/F6wKo="));
    }


    /*public static String encrypt(String key, String initVector, String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            System.out.println("encrypted string: " + Base64.encodeToString(encrypted, 2));
            Log.d("encrypted string: ", Base64.encodeToString(encrypted, 2));

//            return Base64.decode(encrypted, 2).toString();
            return Base64.encodeToString(encrypted, 2);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public static String decrypt(String key, String initVector, String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] original = cipher.doFinal(Base64.decode(encrypted, 2));
            Log.d("decrypted string: ", new String(original));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }*/

    private String convertURL(String paramString) {
        try {
            paramString = decrypt(getHashkey(), paramString);
            return paramString;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private String getHashkey() {
        /*int i = 0;
        try
        {
            PackageInfo info = getPackageManager().getPackageInfo(getPackageName(),  PackageManager.GET_SIGNATURES);
            String str = null;
            info = ((PackageInfo)localObject).signatures;
            int j = localObject.length;
            while (i < j)
            {
                str = localObject[i];
                MessageDigest localMessageDigest = MessageDigest.getInstance("MD5");
                localMessageDigest.update(str.toByteArray());
                str = new String(Base64.encode(localMessageDigest.digest(), 0));
                i += 1;
            }
            str = str.trim();
            return str;
        }
        catch (Exception localException)
        {
            localException.printStackTrace();
        }
        return "";*/

        String keyhash = "";
        try {
//            PackageInfo info = getPackageManager().getPackageInfo(getPackageName(), PackageManager.GET_SIGNATURES);
            PackageInfo info = getPackageManager().getPackageInfo("com.bigappsstore.majedarkahaniyastory", PackageManager.GET_SIGNATURES);
            for (Signature signature : info.signatures) {
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(signature.toByteArray());
                keyhash = new String(Base64.encode(md.digest(), Base64.DEFAULT));
                Log.d("KeyHash: ", keyhash.trim());
            }
        } catch (PackageManager.NameNotFoundException e) {

        } catch (NoSuchAlgorithmException e) {

        }
        return keyhash.trim();
    }


    public static String decrypt(String paramString1, String paramString2) {
        String[] localObject1 = paramString2.split("]");
        if (localObject1.length != 3) {
            throw new IllegalArgumentException("Invalid encypted text format");
        }
        byte[] localObject2 = fromBase64(localObject1[0]);
        byte[] lb2 = fromBase64(localObject1[1]);
        byte[] lb3 = fromBase64(localObject1[2]);
        SecretKey sk = deriveKey(paramString1, localObject2);
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(2, sk, new IvParameterSpec(lb2));
            String newS = new String((cipher).doFinal(lb3), "UTF-8");
            return newS;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static SecretKey deriveKey(String paramString, byte[] paramArrayOfByte) {
        try {
            PBEKeySpec key = new PBEKeySpec(paramString.toCharArray(), paramArrayOfByte, 1000, 256);
            SecretKey sk = new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(key).getEncoded(), "AES");
            return sk;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String encrypt(String paramString1, String paramString2) {
        byte[] arrayOfByte = generateSalt();
        SecretKey localSecretKey = deriveKey(paramString1, arrayOfByte);
        try {
            Cipher localCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] ps = generateIv(localCipher.getBlockSize());
            localCipher.init(1, localSecretKey, new IvParameterSpec(ps));
            byte[] ps2 = localCipher.doFinal(paramString2.getBytes("UTF-8"));
            if (arrayOfByte != null) {
                return String.format("%s%s%s%s%s", new Object[]{toBase64(arrayOfByte), "]", toBase64(ps), "]", toBase64(ps2)});
            }
            paramString1 = String.format("%s%s%s", new Object[]{toBase64(ps), "]", toBase64(ps2)});
            return paramString1;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] fromBase64(String paramString) {
        return Base64.decode(paramString, 2);
    }

    private static byte[] generateIv(int paramInt) {
        byte[] arrayOfByte = new byte[paramInt];
        random.nextBytes(arrayOfByte);
        return arrayOfByte;
    }

    private static byte[] generateSalt() {
        byte[] arrayOfByte = new byte[32];
        random.nextBytes(arrayOfByte);
        return arrayOfByte;
    }

    private static String toBase64(byte[] paramArrayOfByte) {
        return Base64.encodeToString(paramArrayOfByte, 2);
    }

}