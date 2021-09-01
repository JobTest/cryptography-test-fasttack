package com.cts.test.ftcryptography;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;

public class VtsIapiJweEncryptor {

	public static void main(String[] args) throws Throwable {
		new VtsIapiJweEncryptor().generateVtsIapiEncryptedData();
	}

	private void generateVtsIapiEncryptedData() throws GeneralSecurityException, JOSEException {
		
		String cardholderAndTokenInfo = "{\n" + "\"cardholderInfo\": {\n" +
		  "\"primaryAccountNumber\": \"4067592300039516\",\n" +
		  "\"expirationDate\": {\n" + "\"month\": \"02\",\n" + "\"year\": \"2019\"\n" +
		  "},\n" + "\"highValueCustomer\": \"\"\n" + "},\n" + "\"tokenInfo\": {\n" +
		  "\"token\": \"4321098765432109\",\n" + "\"tokenType\": \"HCE\",\n" +
		  "\"tokenStatus\": \"ACTIVE\",\n" + "\"tokenExpirationDate\": {\n" +
		  "\"month\": \"05\",\n" + "\"year\": \"2025\"\n" + "},\n" +
		  "\"tokenAssuranceLevel\": \"\",\n" +
		  "\"numberOfActiveTokensForPAN\": \"\",\n" +
		  "\"numberOfInactiveTokensForPAN\": \"\",\n" +
		  "\"numberOfSuspendedTokensForPAN\": \"\"\n" + "},\n" +
		  "\"riskInformation\": {\n" + "\"walletProviderRiskAssessment\": \"\",\n" +
		  "\"walletProviderRiskAssessmentVersion\": \"\",\n" +
		  "\"walletProviderAccountScore\": \"\",\n" +
		  "\"walletProviderDeviceScore\": \"\",\n" +
		  "\"walletProviderReasonCodes\": \"\",\n" + "\"deviceBluetoothMac\": \"\",\n"
		  + "\"deviceIMEI\": \"\",\n" + "\"deviceSerialNumber\": \"\",\n" +
		  "\"deviceTimeZone\": \"\",\n" + "\"deviceTimeZoneSetting\": \"\",\n" +
		  "\"osID\": \"\",\n" + "\"simSerialNumber\": \"\",\n" +
		  "\"deviceLostMode\": \"\",\n" +
		  "\"daysSinceConsumerDataLastAccountChange\": \"\",\n" +
		  "\"accountHolderName\": \"\",\n" + "\"walletProviderPANAge\": \"\",\n" +
		  "\"walletAccountHolderCardNameMatch\": \"\",\n" +
		  "\"accountToDeviceBindingAge\": \"\",\n" +
		  "\"userAccountFirstCreated\": \"\",\n" +
		  "\"provisioningAttemptsOnDeviceIn24Hours\": \"\",\n" +
		  "\"distinctCardholderNames\": \"\",\n" + "\"deviceCountry\": \"\",\n" +
		  "\"walletAccountCountry\": \"\",\n" + "\"suspendedCardsInAccount\": \"\",\n"
		  + "\"daysSinceLastAccountActivity\": \"\",\n" +
		  "\"numberOfTransactionsInLast12months\": \"\",\n" +
		  "\"numberOfActiveTokens\": \"\",\n" + "\"deviceWithActiveTokens\": \"\",\n" +
		  "\"activeTokensOnAllDeviceForAccount\": \"\"\n" + "}\n" + "}";

		 String jweCertificate = "-----BEGIN CERTIFICATE-----\n"
				+ "MIIDVzCCAj+gAwIBAgIJAI4G8vFkpWXVMA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNV\n"
				+ "BAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAaBgNVBAoME0RlZmF1bHQg\n"
				+ "Q29tcGFueSBMdGQwHhcNMTgwMzIyMDY1OTIyWhcNMjgwMzE5MDY1OTIyWjBCMQsw\n"
				+ "CQYDVQQGEwJYWDEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZh\n"
				+ "dWx0IENvbXBhbnkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n"
				+ "3hrLSEiqo2p8PcQg+fDawqH0R2yOwZe0+DBqLZ3ziCJ6HGAp8b9ul3bV7WKDJLzd\n"
				+ "G5sr1RcJ1s7nCAdPujhgU85o6ZuOOmfpdlacorpOzInPaMUp3/+ht6ni/2sPaIaz\n"
				+ "hdpsw6gYgZt981NhN3xsYJ+pVcvNSrorJJq+o+3pnK910+aOxrdxxO1rahIoxOqn\n"
				+ "3Pb0P2YZQM8WBD7xJrzH5x3r/pWPlAzH+n+ZgT44nUL1RNCm0tokQm43TikV2RU1\n"
				+ "85zGUxTCVM86kabaoZnxSzPIdqwbUNiL0s6c8YqWHEo66C8r81D1T8Is8b1KZmqv\n"
				+ "NJV9qC9cM2dZ/Dd9OdeqXwIDAQABo1AwTjAdBgNVHQ4EFgQUZfSnQ6nF+g08jInv\n"
				+ "fhicmRC23pUwHwYDVR0jBBgwFoAUZfSnQ6nF+g08jInvfhicmRC23pUwDAYDVR0T\n"
				+ "BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAyP3KDFfqg3zWAb56S1lbbk5UNSMT\n"
				+ "MLIHM5UalS2sWnF6j74vTq/v2xccfhE2oCdL3NiIEgiBoRIxl0VOfuYOUTt2XzYf\n"
				+ "aqgK00EjZsnE+4atzYh2n7UEZXmvEX89+OrABXVW0xXHFKGJl6jGHfGo/e46NYGm\n"
				+ "EEZRONsCqMr0vFUr9RT/YTCkr8BGubPIwLb9CBCPoSGj+0s4xs6JC4hLVqlut8wk\n"
				+ "VcpKctKg+T2Lomuii3Dl8G+6kjpGL4NnsOcVExfacfywY0QMHlkOuP/toJYcmhnb\n"
				+ "8Qs5Qsc6AaElbNdlCueszWsfaRf6i3M74LOV07EUMLEhC0kyAZuYpJsHzg==\n"
				+ "-----END CERTIFICATE-----\n";

		String jwsPrivateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDzIHudzXA4d4wD"
				+ "dqhiebkx3i57kBzxXAMKJuuy5zrzU7ZfZNNrRoau1jVE3lI9WAJhuVkZsh0EUjio"
				+ "0ONzlf7QdX6m7JcXUE5GseUoNF4WdP38x3eKGfWESn3giXzMrmcFm+vqTgEUMGGm"
				+ "XFJsWTHhKU4TrUC1i+z5I/nGZgJpbe71hOYmS0VvWVURfK9BHJyQxnRfoQg2qhKt"
				+ "sNB1LBONdjNjRN9VbubC3Nxs/jZjKxvLgEVHMb/QBRSoa0lt1C5kwRNUinVFw5t/"
				+ "yHjJVVv6aY70jDJIQVRIVbkmnDKicUk9Sl1H/LzA+KeB8ohg5dExIjXh1WVM7z5g"
				+ "qNQinxopAgMBAAECggEAJAhvab7V3/iPzr+aSyYBNYvZVcTRFVBuvuVvz08H5KJG"
				+ "iDLYRrDoKydiM7fDdoYBrFwdAXrtZAOPlC2JWEslvd18DN9JsVHcmAuri97fBvMF"
				+ "5Z3mcJhSU+36Y/ncfjVm3WTzfQFclZJqFo7eRGKfyuAlSzNFQOLhFzemwCnEN72i"
				+ "VhtG0x/HnAR8vKzzuPUOdiht2SJmk6+/Fq/V5CF210m9i76xdK+TKRhoXCgesHoC"
				+ "9s+cP6ydKmThrG8YZDSgJog7OL0vILavEyw85+Kir7K2lzEQJCeZTrbcGsA2j0Y/"
				+ "fn/nTpVukP/aR+tGy/PqHgzscgnmg4FxLf4I0NOmFQKBgQD7KLnwvvZarneEV6//"
				+ "2kFBtzXZtjAcRPFzj5oEDg6/f6pqCCSyvuQ9Ta/vc59Hb6EzPA5Ca4E70wAS3PZZ"
				+ "esjiE69pAMe1eT4QVwqrBJkUFowIwqddhr2UGEZ3cJUW0S+Dp5EkQl5xlpcbbCYi"
				+ "0EV9DpwRdJxfK2tX69VLOmJE9wKBgQD30B+5Aq/ajLGdq0kM+DEpDpINuB11XUXz"
				+ "Xhxe60hef2B+cC2cVE6gRJyqOYk9UdLTN1+WIWEpHHYnQ+lpNRfIG9Gm7ZDwZyIo"
				+ "uL6lJmXsDjWnCZqhAzOkMF8YV3qYJ3lPmAGMxRQM2Ps5Ynse+fRFo8ZcHmhssw59"
				+ "mVnF7Qxx3wKBgDPa7cEJ/F0uplh5rknZ6x1BUWn41qgPh/Z/EKKDsIHTPwETW1hY"
				+ "V1Fc59U9fwZFwveMD7mg7pbGcr5yRp6k3jLnM5EvawxJ0wmWnwo+McjW+uSYI+wI"
				+ "dL3N4UapxO5oFDJPd4UP+uXi3KH5y0nmzGIMkSZ9eAeiNFB7zZbxn/ZzAoGBAIUu"
				+ "F+5hMEsfM9GNnTvYIutyxjGTUlmh4BcT6+FjR0hp4lzxQsHyWTMuzJd7RnNrBwe2"
				+ "iatwkvv6LNGbYNTG0NodgUXaBPv+IVCLQQIWqc38MP9tXOnNg7JowKKfWOZuyHZr"
				+ "NeIGhGkHL7S+ZXbXVF0c0FzvhqVscYw0nxeM9xQ3AoGAYIZ7QSFijkuBZd5MZesy"
				+ "smyymTY775fse6LBi5cJk4UIrSp5ax31n7rQW9Lau6j/48P0CSpaxPDJncHS14h0"
				+ "VNAtRULZl3+VVyQRpE8GLGKzZA3AVM29f6qzPG6om/OxaCbSGDjaqMpFIKWsv0qH"
				+ "10x2wonBP+OKLLpsWb87/xI=";

		System.out.println("CardholderAndTokenInfo: " + cardholderAndTokenInfo);
		
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		Certificate certificate = f.generateCertificate(new ByteArrayInputStream(jweCertificate.getBytes()));
		RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(jwsPrivateKey));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = kf.generatePrivate(spec);

		byte[] clearRsk = new byte[16];

		new Random().nextBytes(clearRsk);

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");

		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		byte[] encRsk = cipher.doFinal(clearRsk);

		byte[] iv = new byte[12];

		new Random().nextBytes(iv);

		byte[] eIv = Base64.getUrlEncoder().encode(iv);

		SecretKeySpec rsk = new SecretKeySpec(clearRsk, "AES");

		cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");

		GCMParameterSpec gcmParamSpec = new GCMParameterSpec(128, iv);

		cipher.init(Cipher.ENCRYPT_MODE, rsk, gcmParamSpec);

		byte[] ciphertext = cipher.update(cardholderAndTokenInfo.getBytes(StandardCharsets.UTF_8));

		byte[] tag = cipher.doFinal();

		byte[] eCiphertext = Base64.getUrlEncoder().encode(ciphertext);

		byte[] eTag = Base64.getUrlEncoder().encode(tag);

		byte[] eEncRsk = Base64.getUrlEncoder().encode(encRsk);

		byte[] eHeader = Base64.getUrlEncoder().encode(
				"{\"alg\":\"RSA1_5\",\"iv\":\"\",\"tag\":\"\",\"enc\":\"A128GCM\",\"typ\":\"JOSE\",\"kid\":\"EMNQG2F6OZ0UU1XB2H7G13KcdfTnECeZVHnoznj2FDsmagduQ\",\"channelSecurityContext\":\"RSA_PKI\",\"iat\":\"1519034557\"}"
						.getBytes(StandardCharsets.UTF_8));

		String pkiJwe = new String(eHeader, StandardCharsets.UTF_8) + "." + new String(eEncRsk, StandardCharsets.UTF_8)
				+ "." + new String(eIv, StandardCharsets.UTF_8) + "." + new String(eCiphertext, StandardCharsets.UTF_8)
				+ "." + new String(eTag, StandardCharsets.UTF_8);

		JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JOSE).build(),
				new Payload(pkiJwe));

		JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);

		jwsObject.sign(signer);

		String pkiJws = jwsObject.serialize();

		System.out.println("Signed encrypted data: " + pkiJws);
	}

}
