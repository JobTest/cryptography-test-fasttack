package com.cts.test.ftcryptography;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class VtsIapiJweDecryptor {

	public static void main(String[] args) throws Throwable {
		new VtsIapiJweDecryptor().decryptVtsIapiEncryptedData();
	}

	private void decryptVtsIapiEncryptedData() throws GeneralSecurityException {
		String jwsCertificate = "-----BEGIN CERTIFICATE-----\n" +
				"MIIDizCCAnOgAwIBAgIJAI9bAW3jvs8eMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV\n" +
				"BAYTAlVBMQ0wCwYDVQQIDARLeWl2MQ0wCwYDVQQHDARLeWl2MREwDwYDVQQKDAhD\n" +
				"VFMgTHRkLjEPMA0GA1UECwwGRGV2T3BzMQswCQYDVQQDDAJESTAeFw0xODAzMjIw\n" +
				"NjIyNTJaFw0yODAzMTkwNjIyNTJaMFwxCzAJBgNVBAYTAlVBMQ0wCwYDVQQIDARL\n" +
				"eWl2MQ0wCwYDVQQHDARLeWl2MREwDwYDVQQKDAhDVFMgTHRkLjEPMA0GA1UECwwG\n" +
				"RGV2T3BzMQswCQYDVQQDDAJESTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
				"ggEBAPMge53NcDh3jAN2qGJ5uTHeLnuQHPFcAwom67LnOvNTtl9k02tGhq7WNUTe\n" +
				"Uj1YAmG5WRmyHQRSOKjQ43OV/tB1fqbslxdQTkax5Sg0XhZ0/fzHd4oZ9YRKfeCJ\n" +
				"fMyuZwWb6+pOARQwYaZcUmxZMeEpThOtQLWL7Pkj+cZmAmlt7vWE5iZLRW9ZVRF8\n" +
				"r0EcnJDGdF+hCDaqEq2w0HUsE412M2NE31Vu5sLc3Gz+NmMrG8uARUcxv9AFFKhr\n" +
				"SW3ULmTBE1SKdUXDm3/IeMlVW/ppjvSMMkhBVEhVuSacMqJxST1KXUf8vMD4p4Hy\n" +
				"iGDl0TEiNeHVZUzvPmCo1CKfGikCAwEAAaNQME4wHQYDVR0OBBYEFLCCnmdxUCtV\n" +
				"uuPYxniGpDZQGuv5MB8GA1UdIwQYMBaAFLCCnmdxUCtVuuPYxniGpDZQGuv5MAwG\n" +
				"A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFrBFHRJ70PcaeMRrfTZwadG\n" +
				"Z1yP2e3jtoFlnzmRjSTgWajiaqxFzZa5h8f4sxbJLXrumFHQXP5/aN7X0hZTB/Zl\n" +
				"rkt8chWEDLlU9ZVK7TH9iaoHOTpvwHoFsDpotmsH/PISLUx1RY1z2hJmL0kL4gAT\n" +
				"3OMKf9UwOebG5+dYXDqsO40MUtZCRNWl1DSl/PusBfkgWgW9z3ublGYuzuDR6ruT\n" +
				"2WOPvmkFH7JQfOF8SZV9h0ZdTPcr6zfFegUHbK7gILMh63zvQ+blcEmUhm63BZcB\n" +
				"cykT9Bm7ca80gkyOMNo/BM9NqqAeYELuEL5sibw9q7Cnl6BnY8Ogcd5JGJgdlZ4=" +
				"-----END CERTIFICATE-----";


		String jwePrivateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDeGstISKqjanw9" +
				"xCD58NrCofRHbI7Bl7T4MGotnfOIInocYCnxv26XdtXtYoMkvN0bmyvVFwnWzucI" +
				"B0+6OGBTzmjpm446Z+l2Vpyiuk7Mic9oxSnf/6G3qeL/aw9ohrOF2mzDqBiBm33z" +
				"U2E3fGxgn6lVy81Kuiskmr6j7emcr3XT5o7Gt3HE7WtqEijE6qfc9vQ/ZhlAzxYE" +
				"PvEmvMfnHev+lY+UDMf6f5mBPjidQvVE0KbS2iRCbjdOKRXZFTXznMZTFMJUzzqR" +
				"ptqhmfFLM8h2rBtQ2IvSzpzxipYcSjroLyvzUPVPwizxvUpmaq80lX2oL1wzZ1n8" +
				"N30516pfAgMBAAECggEAI6wuBjgVoBWUSt9bZIl4uVYFxAr9ir5xBIPSKe16ldzj" +
				"u/b+BaP3gUBG78+ovJfQ84QisCD5JZUpqjJybbhsUEmQtCSV3W+fIbCbi89cpKFl" +
				"vLAeH6oRMUyJ9vgdC27HGrKQUYSIGxj8S76SmLTVO1epfOw01tG76C8qe23U3aNM" +
				"MbTewTeWe9j0+pTusTqZEjUyx58khFQxoa1T9RYfC8rbILpP9ZOV/d5bevQGjgr4" +
				"yB0bT6Baqk/oTZQExI18/fWd4rF/+oRAveJuux9+D9IrN1fi5Iq7miAKqUt/SpkR" +
				"LD6e8PlAY54VcXB9XPrcV7xV9GFBOZZRL407U3BCMQKBgQDwurY3ybZfcox207VM" +
				"BaBCm5S+a09TUGNRmyUhf4tNe8yjUb3cjbi5U1BP9t9CkJXqg9qr0wBvSl0tFge6" +
				"XqyRlcHLqxywgDKfCQAx4SENoH/fcmr/uZkkNCGTQFVXRqjMuxic6IQ00AUg7zjz" +
				"b9c3Aon1AcOK2Ub1ITkpqhX5wwKBgQDsMaEtQHYoqXXmWLx13drOAm9eOsXhC5gh" +
				"E18JbdfUKjBhP81SbOybe71Jmx2ZVlSj8qzWc6yDC/Jt8l7hX8uv6Hf/XecsupU7" +
				"aji26tVgZnQEzYGA2hcT1p9NRXaa9YfZvTfAhTnF4IYB8+CkRHIRvfhT9DfUZV+0" +
				"0z/TOqTnNQKBgFBH9DzmqEtsiCuYrv2LYsbT2+clIm9Gf9jXRKrHPk2426YbvJWx" +
				"LcmgX0hLrGkmjtiG4IYs+BglVK2Uiz88E5D5wIeLqSWzmy4uckIwMjW5MOvz3Hss" +
				"CkZonEnfSpawmdqtCqhJYs26EfvJy9RjmAJgdmGfFPdZPrDBQ68BahLBAoGAfdrA" +
				"IGWt0GLjwNbdrQyHL6iagSJeGFleOZmh1VtjWtkUKG2f0WDa/sqDhToTHoai2S1R" +
				"LYA7lySBjFZOelbaKSR89GSr7uiI5jzmdYlSI2jUP07lx6vuChMdlUYDOfTE65/o" +
				"mjwjGa5WmanCtKUIBy4rqUiDizhtM+QwqTQhdFUCgYEAr2Cm+THttIUu/n1XX0lU" +
				"96HFZvzcWEVxyFp4jP28kYtxokXaBMZfEdsGiXGBCMAUu+Lzjr/c3smfPWTFmauc" +
				"D389Mmfrem01wN2+s4LdZMcb5AMe2JJxWjv8q8yiStb8W71c3hw1/am7UdBcaNgA" +
				"Nbkb8pD0efXyybbGGdUDZE0=";

		String encryptedData = "eyJ0eXAiOiJKT1NFIiwiYWxnIjoiUlMyNTYifQ.ZXlKaGJHY2lPaUpTVTBFeFh6VWlMQ0pwZGlJNklpSXNJblJoWnlJNklpSXNJbVZ1WXlJNklrRXhNamhIUTAwaUxDSjBlWEFpT2lKS1QxTkZJaXdpYTJsa0lqb2lSVTFPVVVjeVJqWlBXakJWVlRGWVFqSklOMGN4TTB0alpHWlVia1ZEWlZwV1NHNXZlbTVxTWtaRWMyMWhaMlIxVVNJc0ltTm9ZVzV1Wld4VFpXTjFjbWwwZVVOdmJuUmxlSFFpT2lKU1UwRmZVRXRKSWl3aWFXRjBJam9pTVRVeE9UQXpORFUxTnlKOS5JdVNvV2hQTjBCY1dDaDFWWGJ5Tm9DTFRvU3FxQm4yWEdwaTlsMGs5dUoya3QyTWhDTnFxd1p3RG9yQTdnQVp5ZFhyYllQWlg2V1BXNkNyY01YRWpTV0xrSVN6MFFGdjg3eUJzdXh1TWtyXzd0aU9PV1BQcFJGQWk0NEtPc1VPLXRzZEEtcVhLcmZnNjhrLU9lS2pQbXB3eDBvNUViX0FtWWdvR1NIdklFMXE5UzcybmItY0FkZUtNOVgzZWRSQXRsSXFhSHZXZ2U5REY4NlFJQ1VUQWtSR0Z4bFZBaWlMT2dZYVJzajV0OEpqN1J6VTQtbTc4NTE1cUY2UlJBcFhQRThaTUZPRWYtRzlMcktWMnhCcGxfU3JYTXFVU0MtVFZTNFMwbzk3NnpRMmw4dW44aXg5dVdkUWRsaWFfS1ZTQlhuTUtwWktwS0J4R0JiQk5DSUVZVnc9PS5WVEZZdmFrWlB0Vk9saGR2LkJ5Qk03ekxyUjVFU09hRnVZUTJLLVJ6M2FlUlc2Q0F6V0F2eTYtb0RsMHBFbmtTZ1YwXzNiTHBNYVM4S0lvVC1HelNFNGlqVElhMFBsbHhvTDVRV1NJamlYZDJPRlZyNjZBM0doSEo1SVNWRERQUXlfaENldFlrZWt4b0RoQ3dQV0F1WHBhV1QtbjRNdGFFTTBrMlJUWFdfc09WU0F3VzBtMzRGcTBBQ1dvZGwySEU3Z3FzSG0tcDNiM2ozYklZUm1qRVpSVWJOSVNfQkJFYXhfWHpFT1kwRHlxb0dpajA4MEo4eXludjRfcHJ2YUNGZVhHZHRQN3RoTDQtNUFPWTZyNWV0NXVMR0M2ZUJIaUcxWlNabk44Qnk0d0NBUXFxS3RFclZlV3B4YWVTQkxqTXlUN0Y4VlQ2U2gxM2NtdXM0VnlYWk44WjFFeXQ4ZHhJZmxjNTZ3TW80WDFDSzFwdmlhN0pLZjhnMGpEeFdycjZMcGJ0b29LbUtZbTh5ZEdIc01kQzZsdUtZaXAzb2VoNXNQZHdqdG9kZHlNTzg5VEx5M3NrQnlyajVYVVdBeVFWbUNqcVZ5VjJsTUZqeUdZZ1BBTHA1RTYzV1ZIRXpmOEtIMWlYNlhURTN5ekpwdUE3cVJMVGVFRnkxa1NNQWN6aS1XMGVUeTc1WndScUtOeDhtTHh4MkhvYzRRZWI3cXdxQk41dU14a3BlbWdPVzBFSHI0cWR2MUc0R0hhSHZaTVdzR2ZHOXRPNUN0dm5Ddl90bndEQWdRYWtFWmFJOTZWQ1lSaGtpMGxMRzl5T2dZQ1c5dTUzU0tKenFuSHRTazRCNVJhSzNiZGJXQUtsV0ZoNlRxbUJWVFB0c2dxUXd0elhnYno4ekFMSmNqaHV6MjlMN1UtaXlJTnJIYmRGblZGZFpFb2pXUnhQaGVQZUFJc3IxcHViM1lGTVJWcmctYW5hRTdiS0FkOEwxWm9Kb0hmTXFhWVBEZVZPZTVrRFY3Qklfb3ZKUVNRNEFjcjZNOUM2TF80T2huVEpydnJUTUlSVVBoMUFuaGhaT1FZa20yc3V1b1J2eFhYODdEaXdpQTdubXJDZGFOb2dGaU84Y0FBUTZPUWNqcFJtU0VZY3NtSFpFaHZ1c2ZfcFlLczFtbUFEdDVRTmpZLVJtUkRyb0tBNDJNRi1MV3MyaW9WUk9ZMWZBcVlBVHNFZWtUQTlHd3FMTUxnVkFpSVUzbTFTLW9qZkJONkVZV25KcjBSVWFWZmRmbFc2bjgyX3VKbjJyY29LbFFIX1NXckxJYWZTT2dPZkNjWEtydng2ei1zcHFiRnk2Qkdxbk1wZUdWQWMwQzlWMmptYXZYRWE5aklDdXloemlER28tUl9iendhM1RzdjVYN0Q0TkM4ZFQ5VF9KUExsdEZ5VXp2eUJmY29GWW1RNnExdzR1dWdHbmZjbEhocE84N3U2cGprYVNmOUFLa1hDMnRhWEcyZU5BQTM1ckZJM3ZwZEdfRTBYSzJNNE9mTGNJZUxqVGxUZXpLUW1wcXBJbUw2Q1VSOXRWRUZBbFJra0VhWEEzN2RpNmFkVnVQMUFGYTVuVGpQVHJXQml2cEhfc3IwRnlZejd1bXN4Nlk1bzNjcEkxUTBiTFNveDFXbFA1emNaTG92OHBnLWV3R1NKdVViR25lZE8xUHU3UTdmb09mN1RnVzFtWUJLcU96Z0dDNk9NNXlxaGlob0NveDJQYjl0RVU5dnNKVGlCbmppaHU5MWhqVnFhVm1IeklYUXNhTUgzZHROSU5iUUZTc1lhMnJRYnc1NmdmRzRDSG1PYmpMLUpqQ1lwT2czSGIzMkk0LXpvekUwZWdYdl80d2ZIMVA3cXh0R3ZJRWJYV3dtNzcwYWl6UGthMnVJWFRTWHVCSS00OXc1czJSdlg3a0VMVm4weWpwbzVBcVhELVJUemEteDNYdHpWOWRNLUxrR1QtenNvRHZMZDRDbmQwcHd1SzFQMWRYbmI4TlAwZ1hHSlAwaEpRTDJDV0xKc3RBUnRJV3BrUHNSQVRLS0R5eUFKaDZGMEFvX0ZDMGVMQlcwOUItVF9DZzZKTTRlWnVvS2lmTjkzNEFUM1E1RjBpRXRJMzhpZENOeTF3RG9ITXpRYjJGazFibHVoal9mWVZTVnRiYWIwRDQ5Ui11QXdscWsxaU16VWMxaFBSeEU5d2laZlNVTDgzWktTMWMzMk1QdThxSWdQMi1EQUpocFdnY1NGbF9CUU5qS295SVQyVGtvcEt5X0xROWhiMFVDYy1HOS1MVkdOc3FsM2hjQ0xsR1FxYzdFSmp0NW9uZkdxQnhuNl9qa29kS29vckhMM1ZLWG5EZ2JOYkdZVkFQNGdJa3NycEQtQmdFcDVzaDJabXRXU18uX2NpcXJSXzlEUkdCQmxXRUI5aVl0R3M9.qXLHzx2Tx8sqqBFlvCo1DYZcUujTbkEMmEKv5LuWgUgLo-VFeimvokJIp4NIhJxVVVmypaECE7gQZrsgas2AeD9dUR9MtCWeJKf5PdCEKlg_bMcVsOzWcs55TsW2_y8fKdNPmlbVG12MSng0gx1cAbEJyO-GoCd0ml7CFRZtoDAcMOhxfk7R9fXA1njKhlFjjFXwEUrcQEFq_T6U28b8L33xseuNTiPVk34F5TkL4ki7om-HwJdz8-l92ll4-5UeZgJsI-AI8WMV-4cblyvfBuZATVKcD-_dNUu7tGlXQZ7Mrs2PACB_FUiMkkUtsLZ9iZWA6oGUXgnyAv0j6Y9eCg";


		CertificateFactory f = CertificateFactory.getInstance("X.509");
		Certificate certificate = f.generateCertificate(new ByteArrayInputStream(jwsCertificate.getBytes()));
		RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();

		String[] parts = encryptedData.split("\\.");

		if (parts.length != 3) {
			throw new GeneralSecurityException("Invalid JWS format: must consist of 3 parts delimited by dots");
		}

		byte[] jwsSignature = Base64.getUrlDecoder().decode(parts[2]);

		Signature signature = Signature.getInstance("SHA256withRSA", "SunRsaSign");

		signature.initVerify(publicKey);

		signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));

		if (!signature.verify(jwsSignature)) {
			throw new GeneralSecurityException("JWS verification failed");
		}

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(jwePrivateKey));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = kf.generatePrivate(spec);

		String jwe = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);

		parts = jwe.split("\\.");

		if (parts.length != 5) {
			throw new GeneralSecurityException("Invalid JWE format: must consist of 5 parts delimited by dots");
		}

		System.out.println(
				"JWE header: " + new String(Base64.getUrlDecoder().decode(parts[0].getBytes(StandardCharsets.UTF_8))));

		byte[] encRsk = Base64.getUrlDecoder().decode(parts[1].getBytes(StandardCharsets.UTF_8));

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");

		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		byte[] clearRsk = cipher.doFinal(encRsk);

		byte[] iv = Base64.getUrlDecoder().decode(parts[2].getBytes(StandardCharsets.UTF_8));

		byte[] cipherText = Base64.getUrlDecoder().decode(parts[3].getBytes(StandardCharsets.UTF_8));

		byte[] tag = Base64.getUrlDecoder().decode(parts[4].getBytes(StandardCharsets.UTF_8));

		cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");

		GCMParameterSpec gcmParamSpec = new GCMParameterSpec(128, iv);

		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(clearRsk, "AES"), gcmParamSpec);

		cipher.update(cipherText);

		byte[] decrypted = cipher.doFinal(tag);

		String result = new String(decrypted, StandardCharsets.UTF_8);

		result = result.substring(result.indexOf('{'));

		System.out.println("Result = " + result);
	}

}
