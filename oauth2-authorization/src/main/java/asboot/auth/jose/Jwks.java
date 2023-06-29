/*
 * Copyright 2020-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package asboot.auth.jose;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.apache.tomcat.util.codec.binary.Base64;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

import lombok.extern.slf4j.Slf4j;

/**
 * @author Joe Grandja
 * @since 1.1
 */
@Slf4j
public final class Jwks {

	private Jwks() {
	}

	public static RSAKey generateRsa() {
		KeyPair keyPair = KeyGeneratorUtils.generateRsaKey();
//		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//		Base64 publicKeyEncode = Base64.encode(publicKey.getEncoded());
//		Base64 privateKeyEncode = Base64.encode(privateKey.getEncoded());
//		log.info("publicKeyEncode1:{}", publicKeyEncode.decodeToString());
//		log.info("privateKeyEncode1:{}", privateKeyEncode.decodeToString());
//		log.info("publicKeyEncode2:{}", publicKeyEncode.toString());
//		log.info("privateKeyEncode2:{}", privateKeyEncode.toString());
//		log.info("publicKeyEncode3:{}", publicKeyEncode.toJSONString());
//		log.info("privateKeyEncode3:{}", privateKeyEncode.toJSONString());
//		Base64.encodeToString(publicKey.getEncoded());
//		String publicKeyEncode =Base64.getEncoder().encodeToString(publicKey.getEncoded());
//		String privateKeyEncode =Base64.getEncoder().encodeToString(privateKey.getEncoded());
//		String publicKeyEncode = Base64.encodeBase64String(publicKey.getEncoded());
//		String privateKeyEncode = Base64.encodeBase64String(privateKey.getEncoded());
//		log.info("publicKeyEncode:{}", publicKeyEncode);
//		log.info("privateKeyEncode:{}", privateKeyEncode);
		
		
		String pubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3Sgx30+wj/BYUpg3BvZl"
				+ "mWrfJHOPjym6kKT7zdBUEpzpP2ohmI2NHrl3I7Jb/2fMtoMDvACvKwJMBg2QqxHO"
				+ "hDtc8nJnYPmZtJkdBf2oK60AehbdXxr4geNPl2Iz6mjX8vpNRnZBLIBzRMcZ68iP"
				+ "GyJIl4i9C12m7LDVpMAcxMP3kXEagV7shr0FIOFwkYoe28IBiw5CQc4122hNnJog"
				+ "frC/idDZEP9fnb+pa8Fa2Wo/X8hX6gK9VxO/XRWLTIqu+iB2QBfdx6dWrHEL0JFU"
				+ "ydZ8T3lD0XUQtsRX7qJLZCzmfW+eJcYgay6KNw4UWjYQ6rAZ5Jw51d3l5FTlEWVH"
				+ "NQIDAQAB";
		String priKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDdKDHfT7CP8FhS"
				+ "mDcG9mWZat8kc4+PKbqQpPvN0FQSnOk/aiGYjY0euXcjslv/Z8y2gwO8AK8rAkwG"
				+ "DZCrEc6EO1zycmdg+Zm0mR0F/agrrQB6Ft1fGviB40+XYjPqaNfy+k1GdkEsgHNE"
				+ "xxnryI8bIkiXiL0LXabssNWkwBzEw/eRcRqBXuyGvQUg4XCRih7bwgGLDkJBzjXb"
				+ "aE2cmiB+sL+J0NkQ/1+dv6lrwVrZaj9fyFfqAr1XE79dFYtMiq76IHZAF93Hp1as"
				+ "cQvQkVTJ1nxPeUPRdRC2xFfuoktkLOZ9b54lxiBrLoo3DhRaNhDqsBnknDnV3eXk"
				+ "VOURZUc1AgMBAAECggEARZ+Z08uqsiXgKGBzMmXvplTW2wrmbxOcAF1wSGMFlLaB"
				+ "V815tiUaAEozD7He9JEhCXRFgLJWcxvOAznSCYkZktd9c3ZAxW7OzORHFtO8VcOp"
				+ "GsaH+qDrCzkcnXP1FB7dnUjfewdPjUsC/uwPZQNGyiwI3mvV1/Yrzuf82lkAtZDG"
				+ "Vjyds2sT7GEMzli7u6ETsPRAtp/wyuGIX887PUqIR2dFRcDIvcHPqetlYe/spGKu"
				+ "kLjY/tGo6jnSHBBJDTKYwqn2HgDHrrYtmyXDTZbb4rrrNpmlodX/uXw+mBl0aq8w"
				+ "Dw0InYczX7I61I1ImrkqMR3BoHqTOBaKZRq3hw7UIQKBgQDuwccBvIgHmNOZSfxo"
				+ "FL+CidEOGNK9dGKaUgL0hS2tqi29O6yanMWv5x0woMLHveKQbLoR+GEVQ63jGocn"
				+ "LJjJEYPW0M5/CUu1Rk0qosiEPRAa7SJ1wrY/HM7+Sk3WIcL/9rF3uYC6xf6rhY7R"
				+ "fHfLjKwjOKWweRd4eV4mDjd/awKBgQDtIQYQoP7n0JFCwH3fcAasYCL1frtHH/qB"
				+ "nMHS1Nh6Js59hySPeI+uLZ0FYgHeMkUKhvcfoePeUxdKEkjX5aHRZSdIrdYODIEy"
				+ "ms6htUCCA09jpfnw9H6s4WDzWMo6PuUNXDHlLNgY1ER8PUImeg+bGjgkWtATZ5Ku"
				+ "MQepphcb3wKBgC4McbWEBzhv4V/PRT9NwSIMMqXlY7/mkp3w82D1zrmP+QJmYAPx"
				+ "+K7UhGy8lNSxauEwFzMgFJllVERY+Xg0wcMF/ceQvkMCJ/fudzOh8cqPfGu1ENBl"
				+ "nYDOrZ2d9yU1ncaAbfoJbSqYxWWPfNwqhXBc0VZ5tnsy37P8tIvichHBAoGBAJ0h"
				+ "K+aq+B5eK1NjQEVl81YX4jJwxuJrg1CNsjXlioju3Bd8DLLxPaw6V3kwp3I4N12x"
				+ "b2HLobY5sw4HLbO6W07oy24ymsv2Z0pEILYw58z/KoUqf4O2T5Z5Rggahu6vrJH8"
				+ "zKdC3vMc/UCiSwo6CctKRXd5obWqBR1eKei1wUxbAoGAERw0ullIz8rtGlXN9S/y"
				+ "em6Vs+CfkV/G9ptPKM1fBrITkAwIzv2Yw90OWzJTSwGlzkX6PvHviedob01xI/Oe"
				+ "CPmYCkvaT0Z9p7oqOQP0DNBrDKGQ8fhI5UlCpoOHckY+5Gg30AJI5dI1kprhRD0M"
				+ "sTxVqrBgxFGgFh+jyT9ajIc=";
		
		RSAPublicKey publicKey = null;
		RSAPrivateKey privateKey = null;
		
		try {
			byte[] decoded1 = Base64.decodeBase64(pubKey);
			publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded1));
			
			
			byte[] decoded2 = Base64.decodeBase64(priKey);
			privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded2));

			
			
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// @formatter:off
		return new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		// @formatter:on
	}

	public static ECKey generateEc() {
		KeyPair keyPair = KeyGeneratorUtils.generateEcKey();
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
		Curve curve = Curve.forECParameterSpec(publicKey.getParams());
		// @formatter:off
		return new ECKey.Builder(curve, publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		// @formatter:on
	}

	public static OctetSequenceKey generateSecret() {
		SecretKey secretKey = KeyGeneratorUtils.generateSecretKey();
		// @formatter:off
		return new OctetSequenceKey.Builder(secretKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		// @formatter:on
	}

}
