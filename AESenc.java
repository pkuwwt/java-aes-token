
/**
 * Based on https://gist.github.com/SimoneStefani/99052e8ce0550eb7725ca8681e4225c5
 * */

import java.security.Key;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

import java.net.URLEncoder;
import java.net.URLDecoder;
import java.util.Date;
import java.text.SimpleDateFormat;

public class AESenc {
  private static final String ALGO = "AES";
  private static final byte[] keyValue =
            new byte[]{'T', 'h', 'e', 'B', 'e', 's', 't', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
  private static final SimpleDateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy-HH:mm:ss-XXX");
  private static MessageDigest md5Digest = null;
  static {
	  try{
		  md5Digest = MessageDigest.getInstance("MD5");
	  } catch(Exception e) {
		  System.out.println("ERROR: initialize MD5 instance failed, " + e);
	  }
  }

  private static String md5(String s) throws Exception {
	  return new String(md5Digest.digest(s.getBytes("UTF-8")));
  }

    /**
     * Encrypt a string with AES algorithm.
     *
     * @param data is a string
     * @return the encrypted string
     */
    public static String encrypt(String data) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encVal);
    }

    /**
     * Decrypt a string with AES algorithm.
     *
     * @param encryptedData is a string
     * @return the decrypted string
     */
    public static String decrypt(String encryptedData) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decordedValue = Base64.getDecoder().decode(encryptedData);
        byte[] decValue = c.doFinal(decordedValue);
        return new String(decValue);
    }


    /**
     * Generate a token string with AES algorithm, including information: username, password, date, period
     *
     * @param username is a string
     * @param password is a string
     * @param date is the time stamp
     * @param period_in_seconds is the period of token in seconds
     * @param secretKey is a string used for hashing
     * @return the token
     */
	public static String generateToken(String username, String password, Date date, int period_in_seconds, String secretKey) {
		try {
			String domain = username + "::" + password + "::" + dateFormat.format(date) + "::" + period_in_seconds;
			String digest = md5(domain+secretKey);
			return URLEncoder.encode(AESenc.encrypt(digest + ":::" + domain), "UTF-8");
		} catch(Exception e) {
			System.out.println("ERROR: md5.digest failed, " + e);
			return null;
		}
	}

    /**
     * Judge if a token is valid, by decrypt it and comparing if firstPart equals to md5(secondPart)
     *
     * @param token is a string
     * @param secretKey is a string
     * @return if valid
     */
	public static Boolean validateToken(String token, String secretKey) {
		try {
			String decoded = AESenc.decrypt(URLDecoder.decode(token, "UTF-8"));
			String[] splited = decoded.split(":::");
			if(splited.length<2) return false;
			return splited[0].equals(md5(splited[1]+secretKey));
		} catch (Exception e) {
			return false;
		}
	}

    /**
     * Judge if a token is outdated, by extract the domain information and comparing the time
     *
     * @param token is a string
     * @param secretKey is a string used for hashing
     * @return if outdated
     */
	public static Boolean isTokenOutDated(String token, String secretKey) {
		try {
			String decoded = AESenc.decrypt(URLDecoder.decode(token, "UTF-8"));
			String[] splited = decoded.split(":::");
			if(splited.length<2) return true;
			String domain_digest = md5(splited[1]+secretKey);
			if(!splited[0].equals(domain_digest)) return true;
			String[] domains = splited[1].split("::");
			if(domains.length<4) return true;
			Date date = dateFormat.parse(domains[2]);
			Date now = new Date();
			int periods = Integer.parseInt(domains[3]);
			return (now.getTime()-date.getTime())/1000. > periods;
		} catch (Exception e) {
			return true;
		}
	}

    /**
     * Generate a new encryption key.
     */
    private static Key generateKey() throws Exception {
        return new SecretKeySpec(keyValue, ALGO);
    }

	public static void main(String[] argv) {
		String val = "Hello world!";
		try {
			String val_enc = AESenc.encrypt(val);
			String val_dec = AESenc.decrypt(val_enc);
			System.out.println("Orignal: " + val);
			System.out.println("Encripted: " + val_enc);
			System.out.println("Decrypted: " + val_dec);

			String token = AESenc.generateToken("username", "password", new Date(), 2, "secretKey");
			Boolean isOutdated = AESenc.isTokenOutDated(token, "secretKey");
			System.out.println(!isOutdated ? "PASS" : "FAILED");
			System.out.println(token);
			Boolean isValid = AESenc.validateToken(token, "secretKey");
			System.out.println(isValid ? "PASS" : "FAILED");
			isValid = AESenc.validateToken(token, "no secret key");
			System.out.println(!isValid ? "PASS" : "FAILED");
			isValid = AESenc.validateToken("no token", "secretKey");
			System.out.println(!isValid ? "PASS" : "FAILED");
			Thread.sleep(3000);
			isOutdated = AESenc.isTokenOutDated(token, "secretKey");
			System.out.println(isOutdated ? "PASS" : "FAILED");
		}
		catch(Exception e) {
			System.out.println("Exception: " + e);
		}
	}

}

