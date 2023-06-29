package asboot.auth.test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.apache.commons.codec.binary.Base64;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class Tester {

	public static void main(String[] args) {
		try {
			new Tester().test();
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	public void test() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
//		BigInteger publicExponent = new BigInteger(1, Base64.getDecoder().decode("AQAB"));
//		BigInteger modulus = new BigInteger(1, Base64.getDecoder().decode("qPieq1PFAJqfvAnvS6aKOV8jZAvdxk-ZD2PiV4dAJykMp1iSuiPVw88x4p0TN-_ouElL0Qo35Kxl76mnhBjmyJxV7NciYyIlc0bj93kONhPi0I82DK8ChDdYYMZ9vZexhg6pdpIX3dc33IOqvjHMXoFJ-Gqq_FS9p5hjry_TyiXkvwsGvufkhfo4XPhK6eEF3WNHaPZKdTygK7ghC23bFK2vKQsf6R8dyc4IAHMCjypCq6f1QZbvb2ptUeE6Ut9452tuhzhXIpM-nOpf-sHi5x-togVVaqrlIlAsNEaJLHBS9RZaZP8rSauLwxk2rs5LqxztenNvbe6fu1gLq1SCDw"));
//		RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulus, publicExponent);
//		
//		KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
//		PublicKey publicKey = factory.generatePublic(publicSpec);
//		PrivateKey privateKey = factory.generatePrivate(publicSpec);
//		String publicKeyEncode = org.apache.tomcat.util.codec.binary.Base64.encodeBase64String(publicKey.getEncoded());
//		String privateKeyEncode = org.apache.tomcat.util.codec.binary.Base64.encodeBase64String(privateKey.getEncoded());
//		log.info("publicKeyEncode:{}", publicKeyEncode);
//		log.info("privateKeyEncode:{}", privateKeyEncode);
		
		String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3Sgx30+wj/BYUpg3BvZlmWrfJHOPjym6kKT7zdBUEpzpP2ohmI2NHrl3I7Jb/2fMtoMDvACvKwJMBg2QqxHOhDtc8nJnYPmZtJkdBf2oK60AehbdXxr4geNPl2Iz6mjX8vpNRnZBLIBzRMcZ68iPGyJIl4i9C12m7LDVpMAcxMP3kXEagV7shr0FIOFwkYoe28IBiw5CQc4122hNnJogfrC/idDZEP9fnb+pa8Fa2Wo/X8hX6gK9VxO/XRWLTIqu+iB2QBfdx6dWrHEL0JFUydZ8T3lD0XUQtsRX7qJLZCzmfW+eJcYgay6KNw4UWjYQ6rAZ5Jw51d3l5FTlEWVHNQIDAQAB";
		
		
		byte[] decoded = Base64.decodeBase64(publicKey);
		RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));

		String result = Base64.encodeBase64String(pubKey.getEncoded());
		log.info("result:{}", result);
		
	}

}
