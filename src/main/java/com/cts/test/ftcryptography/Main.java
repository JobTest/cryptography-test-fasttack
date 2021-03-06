package com.cts.test.ftcryptography;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;

import cts.mobo.hsm.CryptoEngine;
import cts.mobo.hsm.Hsm;
import cts.mobo.hsm.HsmSession;
import cts.mobo.hsm.objects.KeyHandle;
import cts.mobo.hsm.objects.RsaKeyPublicData;
import cts.mobo.hsm.util.HexUtil;
import cts.mobo.hsm.util.RsaKeyUtil;
import cts.mobo.hsm.util.SymmetricKeyUtil;
import cts.mobo.hsm.util.RsaKeyUtil.OAEP_HASHING_ALG;
import cts.mobo.hsm.util.RsaKeyUtil.RSA_MECHANISM_TYPE;
import cts.mobo.hsm.util.SymmetricKeyUtil.KEY_TYPE;
import iaik.pkcs.pkcs11.TokenRuntimeException;

public class Main {

    static String staticSignedEncryptedData;

    public static void main(String[] args) throws Throwable {
        Security.addProvider(new BouncyCastleProvider());

        boolean doIt;

        doIt = true;
        if (doIt) {
            new Main().doIt();
        }

        doIt = false;
        if (doIt) {
            new Main().doIt2();
        }
    }

    private void doIt() throws Throwable {
        try {
            Hsm.hsm_initialize();

            HsmSession session = new HsmSession(3, "12345678", true);

            CryptoEngine engine = new CryptoEngine(session);

            boolean doTest;

            doTest = false;
            if (doTest) {
                generateAuthorizeServiceCardInfo(engine);
            }

            doTest = false;
            if (doTest) {
                generateNotifyServiceAuthorizedCardAndToken(engine);
            }

            doTest = false;
            if (doTest) {
                generateVtsIwsiEncryptedData(engine);
            }

            doTest = false;
            if (doTest) {
                generateVtsIapiEncryptedData();
            }

            doTest = true;
            if (doTest) {
                generateVtsIapi3EncryptedData();
            }
        } finally {
            Hsm.hsm_finalize();
        }
    }

    private void generateAuthorizeServiceCardInfo(CryptoEngine engine) {
	/*
         * String cardInfoData = "{\n" + "	\"accountNumber\" : \"5123456789012345\",\n"
         * + "	\"expiryMonth\" : \"12\",\n" + "	\"expiryYear\" : \"15\",\n" +
         * "	\"source\" : \"CARD_ON_FILE\",\n" +
         * "	\"cardholderName\" : \"John Doe\",\n" +
         * "	\"securityCode\" : \"123\",\n" + "	\"cardholderData\" : {\n" +
         * "		\"sourceIp\" : \"127.0.0.1\",\n" +
         * "		\"deviceLocation\" : \"38.63, -90.2\",\n" +
         * "                 \"consumerIdentifier\" : \"12acbf23474561af3d12acbf2347ab12acbf23474561af3d12acbf2347ab12acbf23474561af3d12acbf2347\"\n"
         * + "	}\n" + "}";
	*/

	String cardInfoData = "{\n" + " \"accountNumber\" : \"5354390990000008\",\n" + "    \"expiryMonth\" : \"11\",\n"
                + " \"expiryYear\" : \"21\",\n" + " \"source\" : \"CARD_ADDED_MANUALLY\",\n"
                + " \"cardholderName\" : \"John Doe\",\n" + "   \"securityCode\" : \"123\",\n"
                + " \"dataValidUntilTimestamp\":\"2099-07-16T19:20:30-05:00\",\n" + " \"cardholderData\" : {\n"
                + "       \"sourceIp\" : \"127.0.0.1\",\n" + "     \"deviceLocation\" : \"38.63, -90.2\",\n"
                + "                 \"consumerIdentifier\" : \"12acbf23474561af3d12acbf2347ab12acbf23474561af3d12acbf2347ab12acbf23474561af3d12acbf2347\"\n"
                + " }\n" + "}";

	// Authorize Service
/*
    String cardInfoData = "{\n" +
                "  \"source\": \"ACCOUNT_ON_FILE\",\n" +
                "  \"dataValidUntilTimestamp\": \"2099-07-04T12:09:56.123-07:00\",\n" +
                "  \"cardAccountData\": {\n" +
                "    \"accountNumber\": \"5354390990000008\",\n" +
                "    \"expiryMonth\": \"11\",\n" +
                "    \"expiryYear\": \"21\"\n" +
  //		"    \"expiryYear\": \"21\",\n" +
  //              "    \"securityCode\": \"123\"\n" +
                "  },\n" +
                "  \"financialAccountData\": {\n" +
                "    \"financialAccountId\": \"5123456789012345\",\n" +
                "    \"interbankCardAssociationId\": \"1234\",\n" +
                "    \"countryCode\": \"GBR\"\n" +
                "  },\n" +
                "  \"paymentAccountReference\": \"512381d9f8e0629211e3949a08002\",\n" +
                "  \"accountHolderData\": {\n" +
                "    \"accountHolderName\": \"John Doe\",\n" +
                "    \"accountHolderAddress\": {\n" +
                "      \"line1\": \"100 1st Street\",\n" +
                "      \"line2\": \"Apt. 4B\",\n" +
                "      \"city\": \"St. Louis\",\n" +
                "      \"countrySubdivision\": \"MO\",\n" +
                "      \"postalCode\": \"61000\",\n" +
                "      \"country\": \"GBR\"\n" +
                "    },\n" +
                "    \"sourceIp\": \"127.0.0.1\",\n" +
                "    \"deviceLocation\": \"38.63, -90.2\",\n" +
                "    \"consumerIdentifier\": \"1b24f24a24ba98e27d43e345b532a245e4723d7a9c4f624e93452c1b24f24a24b\"\n" +
                "  }\n" +
                "}";
*/
	//  NSA
/*
    String cardInfoData = "{\n" +
                "  \"source\": \"ACCOUNT_ON_FILE\",\n" +
                "  \"dataValidUntilTimestamp\": \"2099-07-04T12:09:56.123-07:00\",\n" +
                "  \"cardAccountData\": {\n" +
                "    \"accountNumber\": \"5354390990000008\",\n" +
                "    \"expiryMonth\": \"11\",\n" +
                "    \"expiryYear\": \"21\",\n" +
                "    \"securityCode\": \"123\"\n" +
                "  },\n" +
                "  \"financialAccountData\": {\n" +
                "    \"financialAccountId\": \"5123456789012345\",\n" +
                "    \"interbankCardAssociationId\": \"1234\",\n" +
                "    \"countryCode\": \"GBR\"\n" +
                "  },\n" +
                "  \"tokenData\": {\n" +
                "    \"token\": \"5345678901234521\",\n" +
                "    \"expiryMonth\": \"10\",\n" +
                "    \"expiryYear\": \"17\",\n" +
                "    \"sequenceNumber\": \"17\"\n" +
                "  },\n" +
                "  \"paymentAccountReference\": \"512381d9f8e0629211e3949a08002\",\n" +
                "  \"accountHolderData\": {\n" +
                "    \"accountHolderName\": \"John Doe\",\n" +
                "    \"accountHolderAddress\": {\n" +
                "      \"line1\": \"100 1st Street\",\n" +
                "      \"line2\": \"Apt. 4B\",\n" +
                "      \"city\": \"St. Louis\",\n" +
                "      \"countrySubdivision\": \"MO\",\n" +
                "      \"postalCode\": \"61000\",\n" +
                "      \"country\": \"GBR\"\n" +
                "    },\n" +
                "    \"sourceIp\": \"127.0.0.1\",\n" +
                "    \"deviceLocation\": \"38.63, -90.2\",\n" +
                "    \"consumerIdentifier\": \"1b24f24a24ba98e27d43e345b532a245e4723d7a9c4f624e93452c1b24f24a24b\"\n" +
                "  }\n" +
                "}";
*/
        // String publicKeyFingerprint = "2eb15a9ab762ae57e8a008df9f7ea8f89290a1e0";
        // String modulus =
        // "BBAD6CEA3E8C07ECB8E054120B52D74107178C7EFCC064672E03D6FF4BC68A3A1A516DCEBC17E37E37CCC194D774580ED248362A3ECC2524C7633AF1958FFC711C9421A74903D8B0330CCE3FF26E8CAB0645979F3C1F17AF6F6196B91D9208170681BF590E5F069F827124326C2A2BBE32586F872F793FCE707F6F5541BFE794B7BFC2D36FD0B269CFD6F825F2636B4E304B9A55F83CC48D213168CC7AA6826D322218487E800A2992DA31CAAB0BFDF6F977BAA57914357DD117EF72F7F587AE17FA0C36788BF5FB620499A0E6D2C29502DFDC62F9870A7041114C4DB9F5FA31342784EB21D1AAFF9293A8BBD03C487F0D7BFEB0011117BF52318C80AAD511BF";
        String publicKeyFingerprint = "3e70356e5a17b769009bc099c2dcae4b6b82f482a3f59711715d683f7e6fd167";
        String modulus = "00bb054a166b5c99d0c1d4cc0dc7f85ad455b4ed5e82336d5e47588d5cb6d89a7042c40cfd0fa784d6443226fdc2246d4f34e19a43df712ad9f51024391849c3f4b8882df715f49407b2a69e284854fdaf57e36e0a51ac397ef4c18e3c4316fd2593e1622414729b69241bc13b42bf223dbf99d0c3d0f8ffd540b390046b459ef3a8636141e07922661787642f913dc4b08382d9f6b73a6654682a869f0fdbc5c12a1badf4e9e420a8151b1a1ae321efcd2ab502531008c586efc0cb66b769c37436ddf7648e21dff126a49ac8454ecb1a3599688c4e65698dc8cb817d5144054e86b6d77f699ef100dd687b10776ff500a3dc090ac68ba5454d090ee9e3761aad";
        String publicExponent = "010001";
        OAEP_HASHING_ALG oaepHashingAlgorithm = OAEP_HASHING_ALG.SHA256;
        //OAEP_HASHING_ALG oaepHashingAlgorithm = null;

        System.out.println("CardInfoData encrypted data:\n" + generateMdesPreDigitizationEncryptedPayload(engine,
                cardInfoData, publicKeyFingerprint, modulus, publicExponent, oaepHashingAlgorithm));
    }

    private void generateNotifyServiceAuthorizedCardAndToken(CryptoEngine engine) {
        /*
         * String cardAndTokenData = "{\n" + "\"card\" : {\n" +
         * "        \"accountNumber\" : \"5123456789012345\",\n" +
         * "        \"expiryMonth\" : \"12\",\n" + "        \"expiryYear\" : \"15\",\n"
         * + "        \"source\" : \"CARD_ON_FILE\",\n" +
         * "        \"cardholderName\" : \"John Doe\",\n" +
         * "        \"securityCode\" : \"123\",\n" + "        \"cardholderData\" : {\n"
         * + "            \"sourceIp\" :\"127.0.0.1\",\n" +
         * "            \"deviceLocation\" : \"38.63, -90.2\"\n" + "        }\n" +
         * "    },\n" + "    \"token\" : {	\n" +
         * "        \"token\" : \"5345678901234521\",\n" +
         * "        \"expiryMonth\" : \"10\",\n" +
         * "        \"expiryYear\" : \"17\",  \n" +
         * "        \"sequenceNumber\" : \"01\"\n" + "    },\n" +
         * "\"paymentAccountReference\":\"5001a9f027e5629d11e3949a0800a\"\n" +
         * "}\\n\" + \"}";
         */
        /*
         * String cardAndTokenData = "{\n" + "\"card\" : {\n" +
         * "        \"accountNumber\" : \"5168876701114472\",\n" +
         * "        \"expiryMonth\" : \"11\",\n" + "        \"expiryYear\" : \"18\",\n"
         * + "        \"source\" : \"CARD_ADDED_MANUALLY\",\n" +
         * "        \"cardholderName\" : \"John Doe\",\n" +
         * "        \"securityCode\" : \"123\",\n" + "        \"cardholderData\" : {\n"
         * + "            \"sourceIp\" :\"127.0.0.1\",\n" +
         * "            \"deviceLocation\" : \"38.63, -90.2\"\n" + "        }\n" +
         * "    },\n" + "    \"token\" : {	\n" +
         * "        \"token\" : \"5345678901234521\",\n" +
         * "        \"expiryMonth\" : \"05\",\n" +
         * "        \"expiryYear\" : \"21\",  \n" +
         * "        \"sequenceNumber\" : \"01\"\n" + "    },\n" +
         * "\"paymentAccountReference\":\"5001a9f027e5629d11e3949a0800a\"\n" +
         * "}\\n\" + \"}";
         */
        String cardAndTokenData = "{\n" + "\"card\" : {\n" + "        \"accountNumber\" : \"5354390990000008\",\n"
                + "        \"expiryMonth\" : \"11\",\n" + "        \"expiryYear\" : \"21\",\n"
                + "        \"source\" : \"CARD_ADDED_MANUALLY\",\n" + "        \"cardholderName\" : \"John Doe\",\n"
                + "        \"securityCode\" : \"123\",\n" + "        \"cardholderData\" : {\n"
                + "            \"sourceIp\" :\"127.0.0.1\",\n" + "            \"deviceLocation\" : \"38.63, -90.2\"\n"
                + "        }\n" + "    },\n" + "    \"token\" : {   \n" + "        \"token\" : \"5345678901234526\",\n"
                + "        \"expiryMonth\" : \"05\",\n" + "        \"expiryYear\" : \"21\",  \n"
                + "        \"sequenceNumber\" : \"01\"\n" + "    },\n"
                + "\"paymentAccountReference\":\"5001a9f027e5629d11e3949a0800a\"\n" + "}\\n\" + \"}";

        // String publicKeyFingerprint = "2eb15a9ab762ae57e8a008df9f7ea8f89290a1e0";
        // String modulus =
        // "BBAD6CEA3E8C07ECB8E054120B52D74107178C7EFCC064672E03D6FF4BC68A3A1A516DCEBC17E37E37CCC194D774580ED248362A3ECC2524C7633AF1958FFC711C9421A74903D8B0330CCE3FF26E8CAB0645979F3C1F17AF6F6196B91D9208170681BF590E5F069F827124326C2A2BBE32586F872F793FCE707F6F5541BFE794B7BFC2D36FD0B269CFD6F825F2636B4E304B9A55F83CC48D213168CC7AA6826D322218487E800A2992DA31CAAB0BFDF6F977BAA57914357DD117EF72F7F587AE17FA0C36788BF5FB620499A0E6D2C29502DFDC62F9870A7041114C4DB9F5FA31342784EB21D1AAFF9293A8BBD03C487F0D7BFEB0011117BF52318C80AAD511BF";
        String publicKeyFingerprint = "3e70356e5a17b769009bc099c2dcae4b6b82f482a3f59711715d683f7e6fd167";
        String modulus = "00bb054a166b5c99d0c1d4cc0dc7f85ad455b4ed5e82336d5e47588d5cb6d89a7042c40cfd0fa784d6443226fdc2246d4f34e19a43df712ad9f51024391849c3f4b8882df715f49407b2a69e284854fdaf57e36e0a51ac397ef4c18e3c4316fd2593e1622414729b69241bc13b42bf223dbf99d0c3d0f8ffd540b390046b459ef3a8636141e07922661787642f913dc4b08382d9f6b73a6654682a869f0fdbc5c12a1badf4e9e420a8151b1a1ae321efcd2ab502531008c586efc0cb66b769c37436ddf7648e21dff126a49ac8454ecb1a3599688c4e65698dc8cb817d5144054e86b6d77f699ef100dd687b10776ff500a3dc090ac68ba5454d090ee9e3761aad";
        String publicExponent = "010001";
        // OAEP_HASHING_ALG oaepHashingAlgorithm = OAEP_HASHING_ALG.SHA256;
        OAEP_HASHING_ALG oaepHashingAlgorithm = null;

        System.out.println("CardAndToken encrypted data:\n" + generateMdesPreDigitizationEncryptedPayload(engine,
                cardAndTokenData, publicKeyFingerprint, modulus, publicExponent, oaepHashingAlgorithm));
    }

    private String generateMdesPreDigitizationEncryptedPayload(CryptoEngine engine, String clearPayload,
            String publicKeyFingerprint, String modulus, String publicExponent, OAEP_HASHING_ALG oaepHashingAlgorithm) {
        KeyHandle aesKeyHandle = engine.symmetricKeyAlg().generateKey(KEY_TYPE.AES);
        KeyHandle publicKeyHandle = engine.rsaKeyAlg().createPublicKey(HexUtil.hexToBytes(modulus),
                HexUtil.hexToBytes(publicExponent));

        String iv = HexUtil.bytesToHex(engine.mpaAlg().generateRandomData(16));

        String encryptedData = HexUtil.bytesToHex(engine.mastercardAlg().encryptAesCbcWithPkcs7Padding(aesKeyHandle,
                HexUtil.hexToBytes(iv), clearPayload.getBytes(StandardCharsets.UTF_8)));

        String encryptedKey;

        if (oaepHashingAlgorithm != null) {
            encryptedKey = HexUtil
                    .bytesToHex(engine.rsaKeyAlg().encryptOaep(publicKeyHandle, aesKeyHandle, oaepHashingAlgorithm));
        } else {
            encryptedKey = HexUtil
                    .bytesToHex(engine.rsaKeyAlg().encrypt(publicKeyHandle, aesKeyHandle, RSA_MECHANISM_TYPE.RSA_PKCS));
        }

        return "\t\t\"encryptedData\" : \"" + encryptedData + "\",\n\t\t\"publicKeyFingerprint\" : \""
                + publicKeyFingerprint + "\",\n\t\t\"encryptedKey\" : \"" + encryptedKey + "\",\n\t\t\"iv\" : \"" + iv
                + "\""
                + (oaepHashingAlgorithm != null
                        ? ",\n\t\t\"oaepHashingAlgorithm\" : \"" + oaepHashingAlgorithm.name() + "\""
                        : "")
                + "\n";
    }

    private void generateVtsIwsiEncryptedData(CryptoEngine engine) {
        // String cardholderInfoData = "pan=4067592300039516;expdt=1902";
        // String cardholderInfoData = "pan=4363236300018168;expdt=2011";
        String cardholderInfoData = "pan=4567890123456789";
        String wsdKeyClear = "E39BF146C12F0152E661F429979BE3D6";

        KeyHandle wsdKey = engine.symmetricKeyAlg().createKey(KEY_TYPE.DES3, HexUtil.hexToBytes(wsdKeyClear));

        String encryptedData = HexUtil.bytesToHex(engine.visaAlg().encrypt3DesCbcZeroIvWithVdspFormatting(wsdKey,
                cardholderInfoData.getBytes(StandardCharsets.US_ASCII)));

        System.out.println("Encrypted data: " + encryptedData);
    }

    private void generateVtsIapiEncryptedData() throws CertificateException, NoSuchAlgorithmException,
            InvalidKeySpecException, JOSEException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException {

        // token create notification
        /*
         * String cardholderAndTokenInfo = "{\n" + "\"cardholderInfo\": {\n" +
         * "\"primaryAccountNumber\": \"4067592300039516\",\n" +
         * "\"expirationDate\": {\n" + "\"month\": \"02\",\n" + "\"year\": \"2019\"\n" +
         * "},\n" + "\"highValueCustomer\": \"\"\n" + "},\n" + "\"tokenInfo\": {\n" +
         * "\"token\": \"4321098765432109\",\n" + "\"tokenType\": \"HCE\",\n" +
         * "\"tokenStatus\": \"INACTIVE\",\n" + "\"tokenExpirationDate\": {\n" +
         * "\"month\": \"07\",\n" + "\"year\": \"2021\"\n" + "},\n" +
         * "\"tokenAssuranceLevel\": \"\",\n" +
         * "\"numberOfActiveTokensForPAN\": \"\",\n" +
         * "\"numberOfInactiveTokensForPAN\": \"\",\n" +
         * "\"numberOfSuspendedTokensForPAN\": \"\"\n" + "},\n" +
         * "\"riskInformation\": {\n" + "\"walletProviderRiskAssessment\": \"\",\n" +
         * "\"walletProviderRiskAssessmentVersion\": \"\",\n" +
         * "\"walletProviderAccountScore\": \"\",\n" +
         * "\"walletProviderDeviceScore\": \"\",\n" +
         * "\"walletProviderReasonCodes\": \"\",\n" + "\"deviceBluetoothMac\": \"\",\n"
         * + "\"deviceIMEI\": \"\",\n" + "\"deviceSerialNumber\": \"\",\n" +
         * "\"deviceTimeZone\": \"\",\n" + "\"deviceTimeZoneSetting\": \"\",\n" +
         * "\"osID\": \"\",\n" + "\"simSerialNumber\": \"\",\n" +
         * "\"deviceLostMode\": \"\",\n" +
         * "\"daysSinceConsumerDataLastAccountChange\": \"\",\n" +
         * "\"accountHolderName\": \"\",\n" + "\"walletProviderPANAge\": \"\",\n" +
         * "\"walletAccountHolderCardNameMatch\": \"\",\n" +
         * "\"accountToDeviceBindingAge\": \"\",\n" +
         * "\"userAccountFirstCreated\": \"\",\n" +
         * "\"provisioningAttemptsOnDeviceIn24Hours\": \"\",\n" +
         * "\"distinctCardholderNames\": \"\",\n" + "\"deviceCountry\": \"\",\n" +
         * "\"walletAccountCountry\": \"\",\n" + "\"suspendedCardsInAccount\": \"\",\n"
         * + "\"daysSinceLastAccountActivity\": \"\",\n" +
         * "\"numberOfTransactionsInLast12months\": \"\",\n" +
         * "\"numberOfActiveTokens\": \"\",\n" + "\"deviceWithActiveTokens\": \"\",\n" +
         * "\"activeTokensOnAllDeviceForAccount\": \"\"\n" + "}\n" + "}";
         */

        /*
         * String cardholderAndTokenInfo = "{\n" + "\"cardholderInfo\": {\n" +
         * "\"primaryAccountNumber\": \"4363236300018168\",\n" +
         * "\"expirationDate\": {\n" + "\"month\": \"11\",\n" + "\"year\": \"2020\"\n" +
         * "},\n" + "\"highValueCustomer\": \"\"\n" + "},\n" + "\"tokenInfo\": {\n" +
         * "\"token\": \"4321098765432105\",\n" + "\"tokenType\": \"HCE\",\n" +
         * "\"tokenStatus\": \"INACTIVE\",\n" + "\"tokenExpirationDate\": {\n" +
         * "\"month\": \"11\",\n" + "\"year\": \"2021\"\n" + "},\n" +
         * "\"tokenAssuranceLevel\": \"\",\n" +
         * "\"numberOfActiveTokensForPAN\": \"\",\n" +
         * "\"numberOfInactiveTokensForPAN\": \"\",\n" +
         * "\"numberOfSuspendedTokensForPAN\": \"\"\n" + "},\n" +
         * "\"riskInformation\": {\n" + "\"walletProviderRiskAssessment\": \"\",\n" +
         * "\"walletProviderRiskAssessmentVersion\": \"\",\n" +
         * "\"walletProviderAccountScore\": \"\",\n" +
         * "\"walletProviderDeviceScore\": \"\",\n" +
         * "\"walletProviderReasonCodes\": \"\",\n" + "\"deviceBluetoothMac\": \"\",\n"
         * + "\"deviceIMEI\": \"\",\n" + "\"deviceSerialNumber\": \"\",\n" +
         * "\"deviceTimeZone\": \"\",\n" + "\"deviceTimeZoneSetting\": \"\",\n" +
         * "\"osID\": \"\",\n" + "\"simSerialNumber\": \"\",\n" +
         * "\"deviceLostMode\": \"\",\n" +
         * "\"daysSinceConsumerDataLastAccountChange\": \"\",\n" +
         * "\"accountHolderName\": \"\",\n" + "\"walletProviderPANAge\": \"\",\n" +
         * "\"walletAccountHolderCardNameMatch\": \"\",\n" +
         * "\"accountToDeviceBindingAge\": \"\",\n" +
         * "\"userAccountFirstCreated\": \"\",\n" +
         * "\"provisioningAttemptsOnDeviceIn24Hours\": \"\",\n" +
         * "\"distinctCardholderNames\": \"\",\n" + "\"deviceCountry\": \"\",\n" +
         * "\"walletAccountCountry\": \"\",\n" + "\"suspendedCardsInAccount\": \"\",\n"
         * + "\"daysSinceLastAccountActivity\": \"\",\n" +
         * "\"numberOfTransactionsInLast12months\": \"\",\n" +
         * "\"numberOfActiveTokens\": \"\",\n" + "\"deviceWithActiveTokens\": \"\",\n" +
         * "\"activeTokensOnAllDeviceForAccount\": \"\"\n" + "}\n" + "}";
         */

        // token notification
        String cardholderAndTokenInfo = "{\n" + "\"cardholderInfo\": {\n"
                + "\"primaryAccountNumber\": \"4363236300018168\"\n" + "},\n" + "\"tokenInfo\":{\n"
                + "\"token\":\"4321098765432101\",\n" + "\"tokenType\":\"SECURE_ELEMENT\",\n"
                + "\"tokenStatus\":\"DEACTIVATED\",\n" + "\"tokenExpirationDate\":{\n" + "\"month\":\"11\",\n"
                + "\"year\":\"2021\"\n" + "}\n" + "}\n" + "}";

        String kid = "WOC6XE6KEZ4VGJ9KGAWE134SfqGi7Z5PDJuEEzJARbO2XMmWI";

        // test Alfa
        /*
         * String jweCertificate = "-----BEGIN CERTIFICATE-----\n" +
         * "MIIC+DCCAeACCCZn31ZJK+XCMA0GCSqGSIb3DQEBBQUAMD8xCzAJBgNVBAMTAkNO\n" +
         * "MQowCAYDVQQKEwFPMQowCAYDVQQHEwFMMQswCQYDVQQIEwJTVDELMAkGA1UEBhMC\n" +
         * "Q0MwHhcNMTgwMTI2MDAwMDAwWhcNMTkwMTI2MDAwMDAwWjA/MQswCQYDVQQDEwJD\n" +
         * "TjEKMAgGA1UEChMBTzEKMAgGA1UEBxMBTDELMAkGA1UECBMCU1QxCzAJBgNVBAYT\n" +
         * "AkNDMIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQC7rWzqPowH7LjgVBIL\n" +
         * "UtdBBxeMfvzAZGcuA9b/S8aKOhpRbc68F+N+N8zBlNd0WA7SSDYqPswlJMdjOvGV\n" +
         * "j/xxHJQhp0kD2LAzDM4/8m6MqwZFl588Hxevb2GWuR2SCBcGgb9ZDl8Gn4JxJDJs\n" +
         * "Kiu+Mlhvhy95P85wf29VQb/nlLe/wtNv0LJpz9b4JfJja04wS5pV+DzEjSExaMx6\n" +
         * "poJtMiIYSH6ACimS2jHKqwv99vl3uqV5FDV90Rfvcvf1h64X+gw2eIv1+2IEmaDm\n" +
         * "0sKVAt/cYvmHCnBBEUxNufX6MTQnhOsh0ar/kpOou9A8SH8Ne/6wAREXv1IxjICq\n" +
         * "1RG/AgMBAAEwDQYJKoZIhvcNAQEFBQADggEBALo+5lTprrFLzMjGRJaUYHLbjBzu\n" +
         * "7ElT6fKTlvUDWIXhGmUcZheIUdTI98p5niAJmiCOteV4nhpDg6cVlZmZi5sRmxx3\n" +
         * "tDJua3czj5BUfeasm18TtJqMklRGhFNYvKz1eli0zSNqTWhCO9ozy4GLAKaet02f\n" +
         * "a5Xj+DSmqmdMFazNBysLSgIyErH3uUqususjVX5kh49pxsc9zpj1OhR2AaYUu65d\n" +
         * "RrfUYFBBFiOWSv2F7yg93hz3wstdEIL6HnktWQYA8VUh5Tx47WZ0mADoqB3Xo0MN\n" +
         * "1Ns7VlfEBlY49S5+prMIVxlliPAy2hF88K2xUsD1sko7rPaYUVAswp3JDG8=\n" +
         * "-----END CERTIFICATE-----\n";
         */

        // my
        /*
         * String jweCertificate = "-----BEGIN CERTIFICATE-----\n" +
         * "MIIDVzCCAj+gAwIBAgIJAI4G8vFkpWXVMA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNV\n" +
         * "BAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAaBgNVBAoME0RlZmF1bHQg\n" +
         * "Q29tcGFueSBMdGQwHhcNMTgwMzIyMDY1OTIyWhcNMjgwMzE5MDY1OTIyWjBCMQsw\n" +
         * "CQYDVQQGEwJYWDEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZh\n" +
         * "dWx0IENvbXBhbnkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n" +
         * "3hrLSEiqo2p8PcQg+fDawqH0R2yOwZe0+DBqLZ3ziCJ6HGAp8b9ul3bV7WKDJLzd\n" +
         * "G5sr1RcJ1s7nCAdPujhgU85o6ZuOOmfpdlacorpOzInPaMUp3/+ht6ni/2sPaIaz\n" +
         * "hdpsw6gYgZt981NhN3xsYJ+pVcvNSrorJJq+o+3pnK910+aOxrdxxO1rahIoxOqn\n" +
         * "3Pb0P2YZQM8WBD7xJrzH5x3r/pWPlAzH+n+ZgT44nUL1RNCm0tokQm43TikV2RU1\n" +
         * "85zGUxTCVM86kabaoZnxSzPIdqwbUNiL0s6c8YqWHEo66C8r81D1T8Is8b1KZmqv\n" +
         * "NJV9qC9cM2dZ/Dd9OdeqXwIDAQABo1AwTjAdBgNVHQ4EFgQUZfSnQ6nF+g08jInv\n" +
         * "fhicmRC23pUwHwYDVR0jBBgwFoAUZfSnQ6nF+g08jInvfhicmRC23pUwDAYDVR0T\n" +
         * "BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAyP3KDFfqg3zWAb56S1lbbk5UNSMT\n" +
         * "MLIHM5UalS2sWnF6j74vTq/v2xccfhE2oCdL3NiIEgiBoRIxl0VOfuYOUTt2XzYf\n" +
         * "aqgK00EjZsnE+4atzYh2n7UEZXmvEX89+OrABXVW0xXHFKGJl6jGHfGo/e46NYGm\n" +
         * "EEZRONsCqMr0vFUr9RT/YTCkr8BGubPIwLb9CBCPoSGj+0s4xs6JC4hLVqlut8wk\n" +
         * "VcpKctKg+T2Lomuii3Dl8G+6kjpGL4NnsOcVExfacfywY0QMHlkOuP/toJYcmhnb\n" +
         * "8Qs5Qsc6AaElbNdlCueszWsfaRf6i3M74LOV07EUMLEhC0kyAZuYpJsHzg==\n" +
         * "-----END CERTIFICATE-----\n";
         */

        // OtpBankIssuerApiKey.SBX
        String jweCertificate = "-----BEGIN CERTIFICATE-----\n"
                + "MIIDzzCCAregAwIBAgIJANflew9cc3sIMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\n"
                + "BAYTAlVBMQ0wCwYDVQQIDARLeWl2MQ0wCwYDVQQHDARLeWl2MREwDwYDVQQKDAhP\n"
                + "VFAgQmFuazEWMBQGA1UECwwNRGlnaXRhbCBDYXJkczEmMCQGA1UEAwwddWFhZmFz\n"
                + "dHRhY2t0c3Qub3RwYmFuay5jb20udWEwHhcNMTgwNTIxMDkwODE3WhcNMjgwNTE4\n"
                + "MDkwODE3WjB+MQswCQYDVQQGEwJVQTENMAsGA1UECAwES3lpdjENMAsGA1UEBwwE\n"
                + "S3lpdjERMA8GA1UECgwIT1RQIEJhbmsxFjAUBgNVBAsMDURpZ2l0YWwgQ2FyZHMx\n"
                + "JjAkBgNVBAMMHXVhYWZhc3R0YWNrdHN0Lm90cGJhbmsuY29tLnVhMIIBIjANBgkq\n"
                + "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA202KiG6sgloflK9ZkpEmjQbPpPLgIsPE\n"
                + "KETSvYnNjcBJuo5RdKSUIzeUX4j+zhaIp+4aJY94ndVJhVSzv5A7w7jeHrTTQHNS\n"
                + "GVopd4Rv/yeIL6o2WJBwtOTclUF14ngJo5PFnaY7/L4nVKUtYIjdgxpIWleYxLH/\n"
                + "PgU5CFwUadGPaqzHa4GuyK2DxR03bsSIRkTk10j5H8FFDOQLmdBcLYTdoIyFyYHD\n"
                + "YYg1ZMzX33BitzgBJglN6dHg+pO+mw6nov273/KvVqguC08tyHi/EByx92UE2Mij\n"
                + "eDTRGCdgEA4Hh6y9ybhedldtuM6kRX5qg54ofe5rqHFkES8cN7g6EQIDAQABo1Aw\n"
                + "TjAdBgNVHQ4EFgQUW3P2o281MdKPqvQ7Z19EZ75G+8owHwYDVR0jBBgwFoAUW3P2\n"
                + "o281MdKPqvQ7Z19EZ75G+8owDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\n"
                + "AQEAoZ7y1NfPSLdB+lYINJbmBAd38iyfFMTbA98BMNGXiv+kLFM3gGeMbyozyMZ3\n"
                + "beEnIkCbuEQXVZMF+QwYokszbm99hb81mN6QjbanOcXGPIwqFsWP5xOLTxlhH4jm\n"
                + "xqGXoDnrk0nnfsNynRr4doHhQ18oxLMOff6f03ZL2CUq4bDOpYB0+EWUG2O3zHzj\n"
                + "bVUhJopoCeoFTzN3XES9d1rsQYDXFG/ZoiPG3yiCrs0n75RORZktgtEMohVrrNXR\n"
                + "IAtzL/pJZxoKe9RkQIfS0CPUoLTkOQ9vwZWqGUxRmtcHeHd0G3JbaFr+H6tixSii\n"
                + "dJL+UT0WNlzrldT6g7UMKfURIw==\n" + "-----END CERTIFICATE-----\n";

        // test alfa and otp
        String jwsPrivateKey = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDE1C5HFBuf3e7b"
                + "eceeSoze9jutDc4EohsRq+zRGY22afStASj2Sy7gWO9/J6QDxih/EDy8X0EiIQAj"
                + "cm1QB2Y4odlMFyAZGozyC2/0A+ObDzCmi34D5+ucMyReg1B3X795msg1r46fB0MZ"
                + "92aAosRGfQQ/IZB+whFmAMAZmp63yN1vBPznYA3PmU/UdB0bf+9pkI9UtV2JvADd"
                + "rMIhjE0/iXTr0koH9h7wqADCZ5Csgez2rpeChIHtphiVGa5bgqm3kCa6FIOt8Or9"
                + "EkxM1xbOLtTUFkNzWCwHLTllaeFirufaYFXAF+ZW0LthAhVH0hdW7kLxDb9+G+B7"
                + "ekCgcOjRAgMBAAECggEAFqwOLJfPWsnYoqVTbhNOSLx6QUPO0E/P6GgyXh+gaDuq"
                + "OGdizYP5gVQdOjtZtCmWLpSzOkuKmCDPAEZE+yvvBWT3P8GGK/4X8CWLHsN36zuD"
                + "shttR4vmYtatQMnFcgqwZpSCrVRsjDrs6sfJodWd4DS0UYVPPJqkIGjDt+9MiwS/"
                + "bW5uEn+/MN5nQYQ6Mqn+zEWl8eKIGrTkYYAcl/OIg+LWT2r/JMsBFg9PSAgUs6Gr"
                + "R/0Qel8iE0qnGgt5/SeLVbpMVB2wB81E+SgrGoiz8sjlKraJrsouyHqBCxDx6/1O"
                + "vC6TyD3bnCLQDuluYTmJadvAne9wLPoT/UCVhk3T5QKBgQDjDkz8FvsPyBjJGmYp"
                + "f/Ciaz+EakUjRnC//dtjR0fLdF6cuPqNGvKANrtVUozmaGsNOGhIXiKQK7+0yiFQ"
                + "jZZ0jnrDRprTXhZJyxGet1iwIslk88NLYP8BOZPbgyi57UWsqn0aWiZ0Qju5ikEr"
                + "lfUsHNek76e+k1obdUes+XA9EwKBgQDd63TomnsdAPiJK8/nGQ+KF+ejMgs9Gnbc"
                + "ag847+YmDEzIly1hTaheFpeKH74EyUhApAyTUuw4r7uDEdwvQYs0EOq5vhSpGyUb"
                + "iNiNNVOWiVH5KhecKN7LSP6KsiJUKBWdNZut7KcmY7fCmk5iBoJ0WkyFVAoiADbm"
                + "7L6Jya6zCwKBgDp5fl4V1QaVc7ym7dSWPHS3xh3l+HRDOdpYGF4TB2xgRdV61hvs"
                + "6rMWZVxt7BeSoK9A7aplg+U5Px/iRn4mWK8f2oHb9xekTX0nrRwA//gsnU1AcfVB"
                + "v6qjF28a8iwf7SewqJNW0Dx0qkj4UBxXfFKmAutZRQwRis0zgQgNHVi9AoGAHPAx"
                + "RIuwdi3EOw7tg3MvJZDMcel6sbMbwM5Lwd72oguEj7u2/TNFO0+y3x4Yh0NAGr3J"
                + "rgRoLVQtHYBcuATSBC4YjbQNuaeChT6pDnDfv4eUmus0PPbPZq7UEn38IAFCIEf3"
                + "TwzHFyh1s/ivM/UpWcbUp6Y31As3HZHNnuYf09UCgYAjd2p1gE8MfOTEvRDm30tw"
                + "vxAlfYGhUWNdNKiOd0EoaI+R9HUuNYeapgC13TApg36UaMkUqy4UQsgSlTC4Ckzh"
                + "ls8XLx7Nx0VtSrl2jkbQN2VzG4dEa+djkeZGY8PemxBNCEI9oDd+vBIwnUzF9fdF8jcI9wa3WqQNbTRPJp3kjQ==";

        // my
        /*
         * String jwsPrivateKey =
         * "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDzIHudzXA4d4wD" +
         * "dqhiebkx3i57kBzxXAMKJuuy5zrzU7ZfZNNrRoau1jVE3lI9WAJhuVkZsh0EUjio" +
         * "0ONzlf7QdX6m7JcXUE5GseUoNF4WdP38x3eKGfWESn3giXzMrmcFm+vqTgEUMGGm" +
         * "XFJsWTHhKU4TrUC1i+z5I/nGZgJpbe71hOYmS0VvWVURfK9BHJyQxnRfoQg2qhKt" +
         * "sNB1LBONdjNjRN9VbubC3Nxs/jZjKxvLgEVHMb/QBRSoa0lt1C5kwRNUinVFw5t/" +
         * "yHjJVVv6aY70jDJIQVRIVbkmnDKicUk9Sl1H/LzA+KeB8ohg5dExIjXh1WVM7z5g" +
         * "qNQinxopAgMBAAECggEAJAhvab7V3/iPzr+aSyYBNYvZVcTRFVBuvuVvz08H5KJG" +
         * "iDLYRrDoKydiM7fDdoYBrFwdAXrtZAOPlC2JWEslvd18DN9JsVHcmAuri97fBvMF" +
         * "5Z3mcJhSU+36Y/ncfjVm3WTzfQFclZJqFo7eRGKfyuAlSzNFQOLhFzemwCnEN72i" +
         * "VhtG0x/HnAR8vKzzuPUOdiht2SJmk6+/Fq/V5CF210m9i76xdK+TKRhoXCgesHoC" +
         * "9s+cP6ydKmThrG8YZDSgJog7OL0vILavEyw85+Kir7K2lzEQJCeZTrbcGsA2j0Y/" +
         * "fn/nTpVukP/aR+tGy/PqHgzscgnmg4FxLf4I0NOmFQKBgQD7KLnwvvZarneEV6//" +
         * "2kFBtzXZtjAcRPFzj5oEDg6/f6pqCCSyvuQ9Ta/vc59Hb6EzPA5Ca4E70wAS3PZZ" +
         * "esjiE69pAMe1eT4QVwqrBJkUFowIwqddhr2UGEZ3cJUW0S+Dp5EkQl5xlpcbbCYi" +
         * "0EV9DpwRdJxfK2tX69VLOmJE9wKBgQD30B+5Aq/ajLGdq0kM+DEpDpINuB11XUXz" +
         * "Xhxe60hef2B+cC2cVE6gRJyqOYk9UdLTN1+WIWEpHHYnQ+lpNRfIG9Gm7ZDwZyIo" +
         * "uL6lJmXsDjWnCZqhAzOkMF8YV3qYJ3lPmAGMxRQM2Ps5Ynse+fRFo8ZcHmhssw59" +
         * "mVnF7Qxx3wKBgDPa7cEJ/F0uplh5rknZ6x1BUWn41qgPh/Z/EKKDsIHTPwETW1hY" +
         * "V1Fc59U9fwZFwveMD7mg7pbGcr5yRp6k3jLnM5EvawxJ0wmWnwo+McjW+uSYI+wI" +
         * "dL3N4UapxO5oFDJPd4UP+uXi3KH5y0nmzGIMkSZ9eAeiNFB7zZbxn/ZzAoGBAIUu" +
         * "F+5hMEsfM9GNnTvYIutyxjGTUlmh4BcT6+FjR0hp4lzxQsHyWTMuzJd7RnNrBwe2" +
         * "iatwkvv6LNGbYNTG0NodgUXaBPv+IVCLQQIWqc38MP9tXOnNg7JowKKfWOZuyHZr" +
         * "NeIGhGkHL7S+ZXbXVF0c0FzvhqVscYw0nxeM9xQ3AoGAYIZ7QSFijkuBZd5MZesy" +
         * "smyymTY775fse6LBi5cJk4UIrSp5ax31n7rQW9Lau6j/48P0CSpaxPDJncHS14h0" +
         * "VNAtRULZl3+VVyQRpE8GLGKzZA3AVM29f6qzPG6om/OxaCbSGDjaqMpFIKWsv0qH" +
         * "10x2wonBP+OKLLpsWb87/xI=";
         */

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

        byte[] eHeader = Base64.getUrlEncoder()
                .encode(("{\"alg\":\"RSA1_5\",\"iv\":\"\",\"tag\":\"\",\"enc\":\"A128GCM\",\"typ\":\"JOSE\",\"kid\":\""
                        + kid + "\",\"channelSecurityContext\":\"RSA_PKI\",\"iat\":\"1519034557\"}")
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

        staticSignedEncryptedData = pkiJws;
    }

    private void generateVtsIapi3EncryptedData() throws CertificateException, NoSuchAlgorithmException,
            InvalidKeySpecException, JOSEException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException {

        // token create notification
        /*
         * String cardholderAndTokenInfo = "{\n" + "\"cardholderInfo\": {\n" +
         * "\"primaryAccountNumber\": \"4067592300039516\",\n" +
         * "\"expirationDate\": {\n" + "\"month\": \"02\",\n" + "\"year\": \"2019\"\n" +
         * "},\n" + "\"highValueCustomer\": \"\"\n" + "},\n" + "\"tokenInfo\": {\n" +
         * "\"token\": \"4321098765432109\",\n" + "\"tokenType\": \"HCE\",\n" +
         * "\"tokenStatus\": \"INACTIVE\",\n" + "\"tokenExpirationDate\": {\n" +
         * "\"month\": \"07\",\n" + "\"year\": \"2021\"\n" + "},\n" +
         * "\"tokenAssuranceLevel\": \"\",\n" +
         * "\"numberOfActiveTokensForPAN\": \"\",\n" +
         * "\"numberOfInactiveTokensForPAN\": \"\",\n" +
         * "\"numberOfSuspendedTokensForPAN\": \"\"\n" + "},\n" +
         * "\"riskInformation\": {\n" + "\"walletProviderRiskAssessment\": \"\",\n" +
         * "\"walletProviderRiskAssessmentVersion\": \"\",\n" +
         * "\"walletProviderAccountScore\": \"\",\n" +
         * "\"walletProviderDeviceScore\": \"\",\n" +
         * "\"walletProviderReasonCodes\": \"\",\n" + "\"deviceBluetoothMac\": \"\",\n"
         * + "\"deviceIMEI\": \"\",\n" + "\"deviceSerialNumber\": \"\",\n" +
         * "\"deviceTimeZone\": \"\",\n" + "\"deviceTimeZoneSetting\": \"\",\n" +
         * "\"osID\": \"\",\n" + "\"simSerialNumber\": \"\",\n" +
         * "\"deviceLostMode\": \"\",\n" +
         * "\"daysSinceConsumerDataLastAccountChange\": \"\",\n" +
         * "\"accountHolderName\": \"\",\n" + "\"walletProviderPANAge\": \"\",\n" +
         * "\"walletAccountHolderCardNameMatch\": \"\",\n" +
         * "\"accountToDeviceBindingAge\": \"\",\n" +
         * "\"userAccountFirstCreated\": \"\",\n" +
         * "\"provisioningAttemptsOnDeviceIn24Hours\": \"\",\n" +
         * "\"distinctCardholderNames\": \"\",\n" + "\"deviceCountry\": \"\",\n" +
         * "\"walletAccountCountry\": \"\",\n" + "\"suspendedCardsInAccount\": \"\",\n"
         * + "\"daysSinceLastAccountActivity\": \"\",\n" +
         * "\"numberOfTransactionsInLast12months\": \"\",\n" +
         * "\"numberOfActiveTokens\": \"\",\n" + "\"deviceWithActiveTokens\": \"\",\n" +
         * "\"activeTokensOnAllDeviceForAccount\": \"\"\n" + "}\n" + "}";
         */

	/*
         String cardholderAndTokenInfo = "{\n" + "\"cardholderInfo\": {\n" +
         "\"primaryAccountNumber\": \"4363236300018168\",\n" +
         "\"expirationDate\": {\n" + "\"month\": \"11\",\n" + "\"year\": \"2020\"\n" +
         "},\n" + "\"highValueCustomer\": \"\"\n" + "},\n" + "\"tokenInfo\": {\n" +
         "\"token\": \"4321098765432105\",\n" + "\"tokenType\": \"HCE\",\n" +
         "\"tokenStatus\": \"INACTIVE\",\n" + "\"tokenExpirationDate\": {\n" +
         "\"month\": \"11\",\n" + "\"year\": \"2021\"\n" + "},\n" +
         "\"tokenAssuranceLevel\": \"\",\n" +
         "\"numberOfActiveTokensForPAN\": \"\",\n" +
         "\"numberOfInactiveTokensForPAN\": \"\",\n" +
         "\"numberOfSuspendedTokensForPAN\": \"\"\n" + "},\n" +
         "\"riskInformation\": {\n" + "\"walletProviderRiskAssessment\": \"\",\n" +
         "\"walletProviderRiskAssessmentVersion\": \"\",\n" +
         "\"walletProviderAccountScore\": \"\",\n" +
         "\"walletProviderDeviceScore\": \"\",\n" +
         "\"walletProviderReasonCodes\": \"\",\n" +
	 "\"deviceBluetoothMac\": \"\",\n" +
         "\"deviceIMEI\": \"\",\n" + "\"deviceSerialNumber\": \"\",\n" +
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
	*/

/*
 String cardholderAndTokenInfo = "{\n" + "\"cardholderInfo\": {\n" +
	"    \"primaryAccountNumber\": \"\"\n" +
         "}\n" +
	"}";
*/


	    //TODO: Token Create Notification
        String cardholderAndTokenInfo = "{\n" +
            "  \"cardholderInfo\": {\n" +
            "    \"primaryAccountNumber\": \"4244910080876491\",\n" +
            "    \"expirationDate\": {\n" +
            "      \"month\": \"01\",\n" +
            "      \"year\": \"2020\"\n" +
            "    },\n" +
            "    \"highValueCustomer\": \"\"\n" +
            "  },\n" +
            "  \"tokenInfo\": {\n" +
            "    \"token\": \"4321098765432109\",\n" +
            "    \"tokenType\": \"HCE\",\n" +
            "    \"tokenStatus\": \"ACTIVE\",\n" +
            "    \"tokenExpirationDate\": {\n" +
            "      \"month\": \"01\",\n" +
            "      \"year\": \"2023\"\n" +
            "    },\n" +
            "    \"tokenAssuranceLevel\": \"\",\n" +
            "    \"numberOfActiveTokensForPAN\": \"\",\n" +
            "    \"numberOfInactiveTokensForPAN\": \"\",\n" +
            "    \"numberOfSuspendedTokensForPAN\": \"\"\n" +
            "  },\n" +
            "  \"deviceInfo\": {\n" +
            "    \"deviceID\": \"04312E7B342C80014328036811932950DA075B1C4DC45F7C\",\n" +
//            "    \"deviceName\": \"MY BEST PHONE1 with Loooooooooooooooooooooooooooooong Name\",\n" +
//            "    \"deviceName\": \"4p2k77iP0J_QvtC70Y7RgdGP4p2k77iP\",\n" +
//            "    \"deviceName\": \"aVBob25lIDEy\",\n" +
//            "    \"deviceName\": \"aVBob25lIDEyIG1pbmk.\",\n" +
//            "    \"deviceName\": \"?????? ?????????????? 2 (??????)\",\n" +
//            "    \"deviceName\": \"My phone 3 (Eng)\",\n" +
            "    \"deviceName\": \"SgIsbA..\",\n" +
            "    \"deviceNumber\": \"380507534412\",\n" +
            "    \"deviceLanguageCode\": \"en\",\n" +
            "    \"deviceIDType\": \"SecureElement\",\n" +
            "    \"deviceType\": \"MOBILE_PHONE\",\n" +
            "    \"osBuildID\": \"TU84M\",\n" +
            "    \"osVersion\": \"8.1\",\n" +
            "    \"osType\": \"Android\",\n" +
            "    \"deviceManufacturer\": \"Samsung\",\n" +
            "    \"deviceBrand\": \"Nexus\",\n" +
            "    \"deviceModel\": \"ME571KL NA K009\",\n" +
            "    \"deviceLocation\": \"+37/-121\",\n" +
            "    \"deviceIPAddressV4\": \"10.0.1.1\",\n" +
            "    \"locationSource\": \"CELLULAR\",\n" +
            "    \"tokenProtectionMethod\": \"TRUSTED_EXECUTION_ENVIRONMENT\"\n" +
            "  },\n" +
            "  \"riskInformation\": {\n" +
            "    \"walletProviderRiskAssessment\": \"\",\n" +
//            "    \"walletProviderRiskAssessment\": \"0\",\n" +
//            "    \"walletProviderRiskAssessment\": \"1\",\n" +
//            "    \"walletProviderRiskAssessment\": \"2\",\n" +
            "    \"walletProviderRiskAssessmentVersion\": \"\",\n" +
            "    \"walletProviderAccountScore\": \"\",\n" +
//            "    \"walletProviderDeviceScore\": \"\",\n" +
            "    \"walletProviderDeviceScore\": \"1\",\n" +
            "    \"walletProviderReasonCodes\": \"01,02,0G,0F\",\n" +
//            "    \"walletProviderReasonCodes\": \"01,02,0F\",\n" +
//            "    \"walletProviderReasonCodes\": \"\",\n" +
            "    \"deviceBluetoothMac\": \"\",\n" +
            "    \"deviceIMEI\": \"\",\n" +
            "    \"deviceSerialNumber\": \"\",\n" +
            "    \"deviceTimeZone\": \"\",\n" +
            "    \"deviceTimeZoneSetting\": \"\",\n" +
            "    \"osID\": \"\",\n" +
            "    \"simSerialNumber\": \"\",\n" +
            "    \"deviceLostMode\": \"\",\n" +
            "    \"daysSinceConsumerDataLastAccountChange\": \"\",\n" +
            "    \"accountHolderName\": \"\",\n" +
            "    \"walletProviderPANAge\": \"\",\n" +
            "    \"walletAccountHolderCardNameMatch\": \"\",\n" +
            "    \"accountToDeviceBindingAge\": \"\",\n" +
            "    \"userAccountFirstCreated\": \"\",\n" +
            "    \"provisioningAttemptsOnDeviceIn24Hours\": \"\",\n" +
            "    \"distinctCardholderNames\": \"\",\n" +
            "    \"deviceCountry\": \"\",\n" +
            "    \"walletAccountCountry\": \"\",\n" +
            "    \"suspendedCardsInAccount\": \"\",\n" +
            "    \"daysSinceLastAccountActivity\": \"\",\n" +
            "    \"numberOfTransactionsInLast12months\": \"\",\n" +
            "    \"numberOfActiveTokens\": \"\",\n" +
            "    \"deviceWithActiveTokens\": \"\",\n" +
            "    \"activeTokensOnAllDeviceForAccount\": \"\"\n" +
            "  }\n" +
            "}";

 /*
        // token notification
        String cardholderAndTokenInfo = "{\n" + "\"cardholderInfo\": {\n"
                + "\"primaryAccountNumber\": \"4363236300018168\"\n" + "},\n" + "\"tokenInfo\":{\n"
                + "\"token\":\"4321098765432101\",\n" + "\"tokenType\":\"SECURE_ELEMENT\",\n"
                + "\"tokenStatus\":\"DEACTIVATED\",\n" + "\"tokenExpirationDate\":{\n" + "\"month\":\"11\",\n"
                + "\"year\":\"2021\"\n" + "}\n" + "}\n" + "}";
        */

        String kid = "MyFavoritePrivateKID";

        String signKid = "SigningKeyIdentifier";

        // OtpBankIssuerApiKey.SBX (myFavoritePrivateKID)
        String jweCertificate = "-----BEGIN CERTIFICATE-----\n" +
                "MIID1TCCAr2gAwIBAgIJAJl3zo+MsoeIMA0GCSqGSIb3DQEBBQUAMIGAMQswCQYD\n" +
                "VQQGEwJVQTENMAsGA1UECAwES2lldjENMAsGA1UEBwwES2lldjEMMAoGA1UECgwD\n" +
                "Y3RzMQwwCgYDVQQLDANjdHMxEzARBgNVBAMMCmN0cy5jb20udWExIjAgBgkqhkiG\n" +
                "9w0BCQEWE3Rlc3RAY2FydHN5cy5jb20udWEwHhcNMjEwODE4MTIxNDA5WhcNMjIw\n" +
                "ODE4MTIxNDA5WjCBgDELMAkGA1UEBhMCVUExDTALBgNVBAgMBEtpZXYxDTALBgNV\n" +
                "BAcMBEtpZXYxDDAKBgNVBAoMA2N0czEMMAoGA1UECwwDY3RzMRMwEQYDVQQDDApj\n" +
                "dHMuY29tLnVhMSIwIAYJKoZIhvcNAQkBFhN0ZXN0QGNhcnRzeXMuY29tLnVhMIIB\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1RHRzG15Ax++vUvnJKQE5e+d\n" +
                "ZOV+JoWrn+Y0V/BHXiUBYTmBMFiVMr/P9TogptwwPkrDpZ6QH12JZXCHh8QsFmUh\n" +
                "TUwH/JCXaRLA3cs5YmQAAMmzMRim/Sfn4JASJB34O/vjVdYKZU4BaUmhN3aeLRzz\n" +
                "EgGuGGZI+9L+IEtOc2mwcbN+5KfowiHMqjwLTqZHV1cN0W2SpAjPTVT1fAkng3Hb\n" +
                "wU+kVQpYhzJrIuzcw5wBQ+HNc4XelV2u/Ck3s8rZYd2kRi8pkWZwVFw462Z/qPCe\n" +
                "n8xwqmrPO7v30B9pRhi0fsyzUCJj3S9FDOKPan9zFTQC4babrmP/GLmxDSGxJQID\n" +
                "AQABo1AwTjAdBgNVHQ4EFgQUGncx07pfjUSIaXQEnugEQIaj6W4wHwYDVR0jBBgw\n" +
                "FoAUGncx07pfjUSIaXQEnugEQIaj6W4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B\n" +
                "AQUFAAOCAQEAi5+HwFveYw4IrC75RytNvV64kVVjrl1AqQj+WXLSlEP/Wov01Ecz\n" +
                "O73PGy3/0GjnNWgCuBODXPR+5iVf7IhpklweVxoJkisg5+kcORpb2wXSFkXN3rgj\n" +
                "GvWWFvDo0A5ie7R1iMdBgLJs3m5fgFPSgQXPsG+4k8O73FNLKbk7wZnFoW0Z3Q++\n" +
                "K28bL3EuqFyd0+SgAYgDdvI5EHUMfTlN8r/DTNPsbKJ4eeZDXayxWGwx8sr8HF5z\n" +
                "z+MAMcc1dVvz3YAybqCPSDIHp95NZoO9Lfp0i9CmkcB+9UnZgK+z+7eya/mOqZy6\n" +
                "4tCG9xSj/ScwATaW0g/yuvmqeuwuepN2oA==\n" +
                "-----END CERTIFICATE-----\n";

        // My Favorite PrivateKid (SigningKeyIdentifier)
        String jwsPrivateKey = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDE1C5HFBuf3e7b"
                + "eceeSoze9jutDc4EohsRq+zRGY22afStASj2Sy7gWO9/J6QDxih/EDy8X0EiIQAj"
                + "cm1QB2Y4odlMFyAZGozyC2/0A+ObDzCmi34D5+ucMyReg1B3X795msg1r46fB0MZ"
                + "92aAosRGfQQ/IZB+whFmAMAZmp63yN1vBPznYA3PmU/UdB0bf+9pkI9UtV2JvADd"
                + "rMIhjE0/iXTr0koH9h7wqADCZ5Csgez2rpeChIHtphiVGa5bgqm3kCa6FIOt8Or9"
                + "EkxM1xbOLtTUFkNzWCwHLTllaeFirufaYFXAF+ZW0LthAhVH0hdW7kLxDb9+G+B7"
                + "ekCgcOjRAgMBAAECggEAFqwOLJfPWsnYoqVTbhNOSLx6QUPO0E/P6GgyXh+gaDuq"
                + "OGdizYP5gVQdOjtZtCmWLpSzOkuKmCDPAEZE+yvvBWT3P8GGK/4X8CWLHsN36zuD"
                + "shttR4vmYtatQMnFcgqwZpSCrVRsjDrs6sfJodWd4DS0UYVPPJqkIGjDt+9MiwS/"
                + "bW5uEn+/MN5nQYQ6Mqn+zEWl8eKIGrTkYYAcl/OIg+LWT2r/JMsBFg9PSAgUs6Gr"
                + "R/0Qel8iE0qnGgt5/SeLVbpMVB2wB81E+SgrGoiz8sjlKraJrsouyHqBCxDx6/1O"
                + "vC6TyD3bnCLQDuluYTmJadvAne9wLPoT/UCVhk3T5QKBgQDjDkz8FvsPyBjJGmYp"
                + "f/Ciaz+EakUjRnC//dtjR0fLdF6cuPqNGvKANrtVUozmaGsNOGhIXiKQK7+0yiFQ"
                + "jZZ0jnrDRprTXhZJyxGet1iwIslk88NLYP8BOZPbgyi57UWsqn0aWiZ0Qju5ikEr"
                + "lfUsHNek76e+k1obdUes+XA9EwKBgQDd63TomnsdAPiJK8/nGQ+KF+ejMgs9Gnbc"
                + "ag847+YmDEzIly1hTaheFpeKH74EyUhApAyTUuw4r7uDEdwvQYs0EOq5vhSpGyUb"
                + "iNiNNVOWiVH5KhecKN7LSP6KsiJUKBWdNZut7KcmY7fCmk5iBoJ0WkyFVAoiADbm"
                + "7L6Jya6zCwKBgDp5fl4V1QaVc7ym7dSWPHS3xh3l+HRDOdpYGF4TB2xgRdV61hvs"
                + "6rMWZVxt7BeSoK9A7aplg+U5Px/iRn4mWK8f2oHb9xekTX0nrRwA//gsnU1AcfVB"
                + "v6qjF28a8iwf7SewqJNW0Dx0qkj4UBxXfFKmAutZRQwRis0zgQgNHVi9AoGAHPAx"
                + "RIuwdi3EOw7tg3MvJZDMcel6sbMbwM5Lwd72oguEj7u2/TNFO0+y3x4Yh0NAGr3J"
                + "rgRoLVQtHYBcuATSBC4YjbQNuaeChT6pDnDfv4eUmus0PPbPZq7UEn38IAFCIEf3"
                + "TwzHFyh1s/ivM/UpWcbUp6Y31As3HZHNnuYf09UCgYAjd2p1gE8MfOTEvRDm30tw"
                + "vxAlfYGhUWNdNKiOd0EoaI+R9HUuNYeapgC13TApg36UaMkUqy4UQsgSlTC4Ckzh"
                + "ls8XLx7Nx0VtSrl2jkbQN2VzG4dEa+djkeZGY8PemxBNCEI9oDd+vBIwnUzF9fdF"
                + "8jcI9wa3WqQNbTRPJp3kjQ==";

        System.out.println("CardholderAndTokenInfo: " + cardholderAndTokenInfo);

        CertificateFactory f = CertificateFactory.getInstance("X.509");
        Certificate certificate = f.generateCertificate(new ByteArrayInputStream(jweCertificate.getBytes()));
        RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(jwsPrivateKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(spec);

        long currentTime = (new Date()).getTime() / 1000L;

        JWEHeader jweHeader = (new com.nimbusds.jose.JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256,
                EncryptionMethod.A256GCM)).keyID(kid).type(JOSEObjectType.JOSE)
                        .customParam("iat", Long.valueOf(currentTime)).build();

        Payload payload = new Payload(cardholderAndTokenInfo);

        JWEObject jweObject = new JWEObject(jweHeader, payload);

        RSAEncrypter encrypter = new RSAEncrypter(publicKey);

        jweObject.encrypt(encrypter);

        String pkiJwe = jweObject.serialize();

        JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.PS256).type(JOSEObjectType.JOSE)
                .contentType("JWE").keyID(signKid).build(), new Payload(pkiJwe));

        JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);

        jwsObject.sign(signer);

        String pkiJws = jwsObject.serialize();

        System.out.println("Signed encrypted data: " + pkiJws);

        staticSignedEncryptedData = pkiJws;
    }

    private void doIt2() throws Throwable {
        try {
            Hsm.hsm_initialize();

            HsmSession session = new HsmSession(3, "12345678", true);

            CryptoEngine engine = new CryptoEngine(session);

            boolean doTest;

            doTest = false;
            if (doTest) {
                decryptVtsIapiEncryptedData(engine, session);
            }

            doTest = true;
            if (doTest) {
                decryptVtsIapi3EncryptedData(engine, session);
            }
        }

        finally {
            Hsm.hsm_finalize();
        }
    }

    private void decryptVtsIapiEncryptedData(CryptoEngine engine, HsmSession session) throws InvalidKeySpecException,
            NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        // IssuerAPI_JWS_CERT.SANDBOX.2.pem
        // String pemEncodedCertificate = "-----BEGIN
        // CERTIFICATE-----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-----END
        // CERTIFICATE-----";

        // test alfa and otp
        String pemEncodedCertificate = "-----BEGIN CERTIFICATE-----MIIDOjCCAiICCQDTWQKEAhMaBDANBgkqhkiG9w0BAQsFADBfMQswCQYDVQQGEwJVQTEOMAwGA1UECAwFU3RhdGUxDTALBgNVBAcMBENpdHkxEDAOBgNVBAoMB0NvbXBhbnkxCzAJBgNVBAsMAk9VMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMTgwMTI1MTAwMzMxWhcNMTkwMTI1MTAwMzMxWjBfMQswCQYDVQQGEwJVQTEOMAwGA1UECAwFU3RhdGUxDTALBgNVBAcMBENpdHkxEDAOBgNVBAoMB0NvbXBhbnkxCzAJBgNVBAsMAk9VMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDE1C5HFBuf3e7beceeSoze9jutDc4EohsRq+zRGY22afStASj2Sy7gWO9/J6QDxih/EDy8X0EiIQAjcm1QB2Y4odlMFyAZGozyC2/0A+ObDzCmi34D5+ucMyReg1B3X795msg1r46fB0MZ92aAosRGfQQ/IZB+whFmAMAZmp63yN1vBPznYA3PmU/UdB0bf+9pkI9UtV2JvADdrMIhjE0/iXTr0koH9h7wqADCZ5Csgez2rpeChIHtphiVGa5bgqm3kCa6FIOt8Or9EkxM1xbOLtTUFkNzWCwHLTllaeFirufaYFXAF+ZW0LthAhVH0hdW7kLxDb9+G+B7ekCgcOjRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEVffmmLryXA6Ydv3ZWvcB5y7yMfHSdx7VKM1+cWSuoqkr9xvLb3/1q9/Pa2tXkaHqLlz8WQ/u2FBD6n2UqyodBfn2db7dqzHVYLIQiHD/WEmvzH31R6sdPnQCHxZEcLsyiicvBUN3b0pfKxMsDEsbLlJpUe/XVR8V8EQwQOBCq9FcqeMvQtChFgbdp12c2/YBAeOZ0P0Fj9TQc3UHcWz705IKLaXyz0vavJObZ+JaeoT+rBT3sRSgBEoZv+Izkh3hHRGrxGkFT6/ExG05BR8+0A4Bc06bshrkzQ7NH7VXb05T7yXV2rh+qcILKnzhvMtMxl6ZU/znB8LxD2jr/kgho=-----END CERTIFICATE-----";

        // my
        // String pemEncodedCertificate = "-----BEGIN
        // CERTIFICATE-----MIIDizCCAnOgAwIBAgIJAI9bAW3jvs8eMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNVBAYTAlVBMQ0wCwYDVQQIDARLeWl2MQ0wCwYDVQQHDARLeWl2MREwDwYDVQQKDAhDVFMgTHRkLjEPMA0GA1UECwwGRGV2T3BzMQswCQYDVQQDDAJESTAeFw0xODAzMjIwNjIyNTJaFw0yODAzMTkwNjIyNTJaMFwxCzAJBgNVBAYTAlVBMQ0wCwYDVQQIDARLeWl2MQ0wCwYDVQQHDARLeWl2MREwDwYDVQQKDAhDVFMgTHRkLjEPMA0GA1UECwwGRGV2T3BzMQswCQYDVQQDDAJESTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPMge53NcDh3jAN2qGJ5uTHeLnuQHPFcAwom67LnOvNTtl9k02tGhq7WNUTeUj1YAmG5WRmyHQRSOKjQ43OV/tB1fqbslxdQTkax5Sg0XhZ0/fzHd4oZ9YRKfeCJfMyuZwWb6+pOARQwYaZcUmxZMeEpThOtQLWL7Pkj+cZmAmlt7vWE5iZLRW9ZVRF8r0EcnJDGdF+hCDaqEq2w0HUsE412M2NE31Vu5sLc3Gz+NmMrG8uARUcxv9AFFKhrSW3ULmTBE1SKdUXDm3/IeMlVW/ppjvSMMkhBVEhVuSacMqJxST1KXUf8vMD4p4HyiGDl0TEiNeHVZUzvPmCo1CKfGikCAwEAAaNQME4wHQYDVR0OBBYEFLCCnmdxUCtVuuPYxniGpDZQGuv5MB8GA1UdIwQYMBaAFLCCnmdxUCtVuuPYxniGpDZQGuv5MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFrBFHRJ70PcaeMRrfTZwadGZ1yP2e3jtoFlnzmRjSTgWajiaqxFzZa5h8f4sxbJLXrumFHQXP5/aN7X0hZTB/Zlrkt8chWEDLlU9ZVK7TH9iaoHOTpvwHoFsDpotmsH/PISLUx1RY1z2hJmL0kL4gAT3OMKf9UwOebG5+dYXDqsO40MUtZCRNWl1DSl/PusBfkgWgW9z3ublGYuzuDR6ruT2WOPvmkFH7JQfOF8SZV9h0ZdTPcr6zfFegUHbK7gILMh63zvQ+blcEmUhm63BZcBcykT9Bm7ca80gkyOMNo/BM9NqqAeYELuEL5sibw9q7Cnl6BnY8Ogcd5JGJgdlZ4=-----END
        // CERTIFICATE-----";

        // ypylypen
        // String pemEncodedCertificate = "-----BEGIN
        // CERTIFICATE-----MIIEszCCA5ugAwIBAgIJAOsA/5RhU4DTMA0GCSqGSIb3DQEBBQUAMIGXMQswCQYDVQQGEwJVQTETMBEGA1UECBMKU29tZS1TdGF0ZTENMAsGA1UEBxMES3lpdjENMAsGA1UEChMEVmlzYTEYMBYGA1UECxMPVlRTIEludGVncmF0aW9uMRkwFwYDVQQDExBZZXZoZW4gUHlseXBlbmtvMSAwHgYJKoZIhvcNAQkBFhF5cHlseXBlbkB2aXNhLmNvbTAeFw0xODA2MjcxMzUxMjFaFw0yODA2MjQxMzUxMjFaMIGXMQswCQYDVQQGEwJVQTETMBEGA1UECBMKU29tZS1TdGF0ZTENMAsGA1UEBxMES3lpdjENMAsGA1UEChMEVmlzYTEYMBYGA1UECxMPVlRTIEludGVncmF0aW9uMRkwFwYDVQQDExBZZXZoZW4gUHlseXBlbmtvMSAwHgYJKoZIhvcNAQkBFhF5cHlseXBlbkB2aXNhLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN4n1L+XP+1seNuX8yfhLLDFJ4ry3OJwjh1IVfukH1PASt3anSuxBHLV+Bpqnq/1sirMhkSA6svKbKLIoXrn5Dazp/kcGBOHt1OgtsRMoF3TYGqU1pLQUQg4OqoYZG7Gc/qGzcqbSQWZLcjWrhpPQix+3exeKIe6KkxYG3LY1+6S1/LGOZrqOsQB2Ow8DIeT6YbUdYazSYix/heW4LdCDnB4WP1wSuVKwoctbuelsIpOy66xxD6T/YhkFpI80750CRLwRmlMLfbgfvfFk8OYIaVbQjbyd7Yma9NMyF5nQuf4zSREDE39P8a3bu3Tt1XyN6neYtT9fe4MSaNUwHl4sd0CAwEAAaOB/zCB/DAdBgNVHQ4EFgQUvhv4YxrWS7xAjSCGfrbtB17V9pgwgcwGA1UdIwSBxDCBwYAUvhv4YxrWS7xAjSCGfrbtB17V9pihgZ2kgZowgZcxCzAJBgNVBAYTAlVBMRMwEQYDVQQIEwpTb21lLVN0YXRlMQ0wCwYDVQQHEwRLeWl2MQ0wCwYDVQQKEwRWaXNhMRgwFgYDVQQLEw9WVFMgSW50ZWdyYXRpb24xGTAXBgNVBAMTEFlldmhlbiBQeWx5cGVua28xIDAeBgkqhkiG9w0BCQEWEXlweWx5cGVuQHZpc2EuY29tggkA6wD/lGFTgNMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEA3eKDaJaP0zZ1OSVzYXB1KDZjRHWQrqEE3yiCOcPOzQJKa6uXviYRokjfqLdLcewjyoe6dbhxh+6iYBXjSCeGUo0R3T+dgnB5g4PtRmLBP8IMjvb7kBPkCRP6cjUBKJ4BKZII2tTjWGwKD2s0eSp+r6ynjsEzuosi6lBukzewGwBIF5FE82b7InJNNZsKrgmWyy7KhGTNFgzGbM3vMGBFgzdn22fbBGmXLaH2SPOV0gSx0zNFXaQvB8BC1uSpP+UMjqJtWiLiZHsdt08KK029OPI56rcpjFCBrZq2opdq2d7x+dd/F4+/ZxvhJq26BlH8U0bCGhxtJyM9fycDYJtaIA==-----END
        // CERTIFICATE-----";

        // my
        // String wrappedKey =
        // "EF44A6D278BF166A50D2B633B575BA62FF7992ECBE94CEFF470213300CA5B2AC9504C40369DF7B0B57EF6AA8DAED707C874B58E3358EA295237B51BE9EB3A64E8173469F3E52A74337354800D5264A2ECA2A73AA424B0393A4735E6D3AAD58DC3EB85F89DF885038C5155DA20FEEE6A90AE49DB9D3D5B2564ED261622550326FF8402496FD8BD4CE1E5FACE48087BC4507C46C5D2243928B20E339A9599D67444EA2A879B916346B2A58800F8919B8896B452BD996FF697659094E20FCBF73B091D9A0641DA31F37EB2A58D76E1B096BD34F6405259388FFF8FE86BFC647A0C1627797AF3F7BF9097E067AAB917D2B0544E541BBF0DE11D02D348619F7D54F86D0B206DA7D838FED8A46364151D92F234D931B78C7878486A55D4B7AC3EB67DAC2D96EC2C44035382647759AE8021645D9B7B0335EFD3CA1F079BDEC1229395B6BD2BF5BC7630AFD00E23E9059DA8D2C93B4BDC023C3A9FC4D66F1FE563D6E8C21ACFFB13F5B38F6F4F88EF2D10FDD8553DE800C9439CE19128CAC4406527404919B080B6A041930D9D3034073FBDF7D71F1B8DEED85CBCFD5EC88FF1DD00260526C6D0C974863CC3BEFF2F6BC99E0F42B68314149A9845629922FA9A3D51A7B53F96EB4C370118278F1A4F69ACB0F517F8289DDD32C912FD2B94782BD0D116AAA599470736D5DEF2A4F542BA40D1AF4A04897BC8641A416B8EA9F2566A7D663ECC9EB003D913510D4DFCFCC89A060A6274DF45FF69F9CACFD50B712E4B735AAE48865FF8853A93491B4B2A2B7B0FD316D5737EF0B62AFAAA628EA57CAC42F965B9C8AB3952C024C6ABD8A5176C36B32679A7B8AD2DC97DF76746D6495AF1CC5727F394D452C428C02480DC8A6D19E07EEFB8937E09E2ECDD14D9805517F91FB3B27502B53FF41C60926255130DA97B278B14A1BB685744A3CCC241B8ADAC2726167D216F112C8D97BF39138B5F55ADC5B83B31620C6D996173A2C0887B288ED5001C8F5F5388B1EE450607788CB2619961E3571EA25E342B6895BC87B63F71BCBE0AAD24281FF21DB2C635DA9141AB920FDB0619E6D86BF35E71C7A0B5EF15D283305B0533D75369435D778AD121752393936B304A4AC7A4494105EF8D90025542F93F7C2D4634846DA7670E39D87E45D5770AC3F7EB271B3537D13B38481976FBD7C1E8C9B9242534EDE4F452CA48CA9A16743246875311F35285A5A047F230B1548C30D2C02F41D40AD0BA1CB9FEE8A5ADCA0B1E59DD3E9E8B154D19BD76F93AC8BEF9AD8D157069C8C06B76A06AB1CE969CFF788B60E960A5282CD81EEB5602235426348835E6BFF283900E2F25430F62472329A850BB12066CB7FBF10E39BB44E61A6DE2C9F148A8141A508AB6C4ED870442D9163B18F0174DF0D59639490A5029B9C4378899F0E7C1319834AC840BA282C074FBF36043CB552BC6E073881CED671DD2C5B6F36E71326B58F101F64D5A584B5A10EC177B271367FBBC29F42989BD6A6FBCE04C11A1E948A0A853F937679339041010D1DBF53E487EBB553EE3701FE9CE5DCB68253BA8519C048B1E8892272DE2E31D997B52A2BA431272A27127C5018C13DDD24C649ACA5848DF0D675108979BB03794BA40794950469FA0D335C2E09B95C09FD8C8E6127BEA6E38C3CBDC4535B2C3A13B29513C3A01C3A814E9CBF34FF2D0FDCD04BF0FA558876CE7D3499EDF3FCEDC4AA3066B26972A37CAA6B98E96333DADE2F4E88D458CEDA";

        // OtpBankIssuerApiKey.SBX
        String wrappedKey = "AE5CC0A0D072BCEF8C2765F34626839AB70522D09C11DA5C0B04AEAB46078BBDED2224C08E4E2899618795ED7A7350AB2A68175AF6F980AD589C7A644B53AF7BDBBFF8F2281784C7F69B278F8F32FD427631DDFE63812584CB425AD3CBF4E86476A95A65932C680D34FFF42B4E8EC6644A72262D2F8A8D77E3754A1B339B69EDAE08315473967F85BCB4574F57121DD11348F0E46D62404AC8BA1FF81EC09CC8DBDBDCEA7C1B50FDE8F28ECB826AE521294845EE485251DFC58284FDFB9B9FC2E7CE8DB8C3E385C43C3653EF655711C80B1282BD9479CB2648F68FC63BF30647664C4AAE4D857C6E1C78E0FF3473090CCF79CD236671343A9F8B209CE1807C1FE94331A1D39A6605D2CC3A52A1ED1AC98159CC33FA40F1CA6D0702F36B9A251517FABA31DC9CDC2D3D285E3C8BE08F172E844E750282DD9A77101A83F33CC18E8BCC7E4FA953FFBB8475BDABD1BD6A6BE8453BB886EEC31835183C437AB9BE97DAA481ABD42E7DEDEC6B2BAFDD794882FB9D06CA7CE87CE2777C00ABFB7E9BAC8CF434AFA1BAB1241BB541CDEBD42E7830E166AD1F7049FF1E4ED11C499B4D9314B9AF300167208E333057642306BCA9F91A2323580DC6419EFB646CD5AA015A6B956E98B2C5F7F47C6D15D796098A1A3C4E9DCE4CDED388277BE2897441BEBF081EB5C89FBE590206379CF6BA32006B602F03E4366E1BEF6BBD3865EEFEFB1B0218B9B1578DF3D11F8A822AF48807B946DE4C653D024778FD42703DA58AE215189ADFE516130338CF523BCBB1E5D15E1DB046BB534E1B857DECF93A954629B5D69E85C698DA9C6960180C892A8911CF9538B4584B19589DE9F10307D167B021DD4638D07820D73A2809012779705542BF90384D220E690DFC4E905A46644FE2E7A681D4760190FF44575535F8DDC661501E2F6F0C2160B1B47C4E2CE989D80B806290A418274FA1BA701BA677DA3651B89AE9500234F02EBE5E17CBC6395F908B0ED54EBD036C872C8F6E2AF5695FC685729C08DC5D4280CD08FAAA325E3AE160A7F8F58CFDA63732EBD99DF6D96921F775781D5D859074C5975473F8C82D60C6BE1021588B410637F03CF86BCA471AA173C9ADBD6B0111D6AD53B0828F636BCEE83EF970799D6964C1E552A5E0FDE259FB9F70C0718916D6F2403B7F6CA12D40F90EA4077DEEB58579A21968100E4266DF363CEFDAEA5F7DA575FAA8C8D8C92B4890B3D445ABA8F2612595B86757A9E9DA055F8769681AFEE8925027CFA4E912C128DBA1CC42ACD10D0D0AB71273EB42600C9444DFCD42600D462F19D3C643E57A2F5C1AC450A80705398B0890D3058CA7B3364D8ACB8DE3F1CB70E578A6E45052AF0039663E935FCCFACA6A372AFCA8703F4EF2F3ABF14F10A9C176A8ACAA12B54BC7289EA163A799596E04CAEA3BF8113B638DC1630E818C60CC6360BD993FF25B124B67B7781DE1231B7B3EC995A038E787DC59492A82640C1B2639BC9373B3A3430A38F77122DBDCAC62810820A12BA5678C9D1D1B0F96A186D2A498829804F3DED3E9C6FEBF083B4DBE6D074CE0DBB605EAE152146CB7D6455B722C294B29FD3B90499A0EAC4F2D4E1AE47C8068CF7F481E6AD6D36D57856E771E21B35CFBE5421B282247CD14ED79B6A669310B29EB4E9B250503BC3FBFBBADB1538A01890D82AA0EB3A6FD2232580E48E91FFEFE8AEEEF733A2F436562153DEEE46C";

        /*
         * String encryptedData =
         * "eyJhbGciOiJSUzI1NiIsIml2IjoiIiwidGFnIjoiIiwiZW5jIjoiIiwidHlwIjoiSk9TRSIsImtpZCI6IiIsImNoYW5uZWxTZWN1cml0eUNvbnRleHQiOiIifQ.ZXlKaGJHY2lPaUpTVTBFeFh6VWlMQ0pwZGlJNklpSXNJblJoWnlJNklpSXN"
         * +
         * "JbVZ1WXlJNklrRXhNamhIUTAwaUxDSjBlWEFpT2lKS1QxTkZJaXdpYTJsa0lqb2lSVTFPVVVjeVJqWlBXakJWVlRGWVFqSklOMGN4TTB0alpHWlVia1ZEWlZwV1NHNXZlbTVxTWtaRWMyMWhaMlIxVVNJc0ltTm9ZVzV1Wld4VFpXTjFjbWwwZVVOdmJuUmxlSFFpT"
         * +
         * "2lKU1UwRmZVRXRKSWl3aWFXRjBJam9pTVRVeE9UQXpORFUxTnlKOS5OakRuTS1DS0l0TldKMWlSdDhCb3NmMUg5LWRUN2VnTl83X0dQT0NGNjctdi1McGl2eVB6eEI4NzV6Y09QckJkZWlZbnVjSHRhNDZFN1d3UTBfZ2RiUjJ5eE5HZjd0Mkd6YlNFdUhtdUtSNll"
         * +
         * "EZFFfMHhfYkZfaU5HLW5PRDhDNmg5SG81RmNuakh4MThiLXdxUXNMY0ZPQ2lubmRld0xTVUxrZGZaTlJyalNqUi1uRHRybWNzOEZ0UUZMSnNleFV5TDQ4OWF6SlFsSU44a1RBNng4MkRaTHYzV1F6QldaLTJuVURvcEp3RTM2bTZuaUM3REJBbmpTd1hkQ2s0eTFLa"
         * +
         * "XZ4S1ZNbVlMRkQ3VEFxMXdBME1xNjE0cnVMbm5WampwZHkzZUx5MHNfUndySmFzNVNOQ2QxV2RuT3hkZkFfcHB6UC0yNE9yX2dLNDBDU2tmUU5NekEuTnh0c2dlSGNELTFqeWt2US5ncVphNS1sZGY0STZiMTY0c2dwWURhaG9iTXpKQmk2ZWtYMjdWMEJBcTQtS2l"
         * +
         * "IbnFGSnFfcHZrZWZ2bEZtVGk2MHhBeVBTT1ZvYmE2cm5qQTQyMzhkbVI5ZVNfZ25sNjJEbWE2a3hvVlZSUEh6eFlTWFBuRmtuMnZuYWtuWHRlczhZMzJpa3ViZWh6U3kyWUllUDV6Zkp2ZjVsV1YxTEF6WGJoT1dWTi1zdmdldlRHNFAtcVExWTVYLUNDTUFhRXNPT"
         * +
         * "UNIbUZDdG51MklyNHVCcUx3Uk5ZYU9SaTR0R2wtMmhsdUhkdF9mWWd6dnFqejdjalppSmY0RzNvMDdVMUhUZ3JtTDR3XzFidy5XWVNwTnFIMTNOMTlXNkpIZk1oTXRR.iOd6hhB5rxa0y6vymGV6AHX_Xxigugsop_NyaC92TDjomEJsyKE4eq-Dmwh_utfzk3IIyW"
         * +
         * "NpyydGDpsalVgliHcGYSyS2Gl2OMl0mBgjT8MPnKrLSnHG198dMP6an-ClWM6xjawHIAwI1_fUsGCB5Xa9KWtqOvPNDH9LfBB2YJ_g9aNmX5mSqu9y_R9eZ8HRb-OPwH_rVPOJvfmVe7WEQSbU8uD7uVro2-WW-nU15WtxlWkCS3Z8YPbBY_Wl08OToNRab2_AkBT6"
         * +
         * "_komCz0Q7qnMCSQ8S1PHliBZV61jsQZJOw3_jFB7OTORTtM_V_SNBc0G61E7t0K9pr_iIY6sBQ";
         */

        // String encryptedData =
        // "eyJ0eXAiOiJKT1NFIiwiYWxnIjoiUlMyNTYifQ.ZXlKcmFXUWlPaUkzUjBoWFN6TlJUMGhHU0VrMU9UWldRbGRTUlRFeFVXcFVWekV5VEdOVU4xVk5MVkpUUW05UFEzZEdkWHBTUW1KVklpd2lkSGx3SWpvaVNrOVRSU0lzSW5SaFp5STZJaUlzSW1Ob1lXNXVaV3hUWldOMWNtbDBlVU52Ym5SbGVIUWlPaUpTVTBGZlVFdEpJaXdpWlc1aklqb2lRVEV5T0VkRFRTSXNJbWxoZENJNklqRTFNakUzTURVME16WWlMQ0poYkdjaU9pSlNVMEV4WHpVaUxDSnBkaUk2SWlKOS5SNEhydDFRbEhzZWhyblY3cjNveUtqOHNUSTNiOVRVOWh2dWpJT0E5ZWxaV2NMWHRYMWVGSlpreVVKMzRVTWVyaDA1ZDc2TXZmamhzWWIxbnVkTWM0dmFXdjlqdXRWa0dOWFhYS21EY1hPcDhpWnN4LTM2a0pRandIbjZmTFV0aVE0OENadHQ4eWduV3VqYmlod1Zpd21XV2pWWHVrNXdqNXdBTlFSbUl3LXhGd2JVclRPUkNBSEFZR1pjQ1dJN29wUVVuNzNaT3o4cElkOEFNV0R6QllrYThkZ3NyaC1QeF84THd3cGdycG10ZXAtcHkwOHBKNkt0YlEtLW14Y040enZ0RGpzakpPeEROdHE4MjhqQUdfdjRFazdGWjR4T25CMmFYeGIwd0RkRXA5M3otM2Fkeng5NzRKS1ppbTNiUmpCVVBncGlJWUFYT25FdmdNVndLMncuY29CV2J6TDZJLWRVMjY2Zi5weVJUMlJpaWwwVzhyQnd3N1ByaS1uUG1pelhZNGJNR0UwRmluZW9vejQyUmlvTlE1ZWZaUEd6alJELXJGNTN1WDVTN2VXWUFDMlBRMEtDckhHZnk5b0JTZzRaNzNSeGlXQUYwdVRsVFRnVXdBSHNlMm5wMDJEV18wWGswWUs5Y1dsa3NTenF6ZjRlMWdhR1dEMnExMC1rMzA0MEptTzV5NjkzR0VFNWhrMkN2WnFMRVBOYjhxWlNrTGdrbUVxbG5GZm5feFZ0X0R0ZTNhX2IwWndFczE0cjV1YjlodTRnUkNqY1J1a1c0Y09TcHJJVVNaQ3NJMkxxYXo5bE1wLUstOGk5ckp6MERHS09UOE8yYWZoUkR1bk5XUjFKdmdrdjR4Z051VmpzX1dFdExmaFlrbDdHdmMycWo2MnJWSDNUTU1iYkRBMTZIN2Y5RXFNb2h1Y1VMZU1lbXM4WG83YTF6bjItYTJBZTZlYjZUeGtXZVNEUWczdlBxTDZUWHZjRXBQbFRrWTMtd2RwNGdHeGZQcmRKNFlxdkU2WEFRclh0R0xjY0sxY2V2YUZXanl1M2lRNktEaEctanR6ajZENEpHWHpBa3ByWmRtOTlwMXdCbE5FM0JoSFVvVTB1N3J4ZVZzNlRRSDhwLUlBQ25tcE0ya2ZHaGQzNWR4V1lVTGo5RTNUYXZsX3FJbF9DZk9fS25zX0doa2ktdlJuTWlMWEtBN2wxaXQ2dGVabWxzS0RHbUZzVzc3RFd3YURHQ2ZONEI0OWRkNWxEM0hFbmVpcVZNb1Y2dU9nZTFhSjUzcVUyZGl4TmUzNUlIWElBMC1oSW9lUG1RNU4zYndwZWEzMUp4eXZyM3RyMDJnNEowejJ5NkE2bXRYdkhkQ18zMXVkX1A3RjMwalVWS1MxcWZPTE1OTkJuWGN6NVJqc2Y1ZW41cUpCaVNXV3JRbkg3TDNaeTYxaXNPZlN5cWtHVDZZRWVFVGhDMC1TZ0ZNUWVaS0ZxNlZVZXJDNUg0Y3RnQmN5OHRhV2dycGRWZmRkVk0tT0lBenpGcm9oNTNHVG5TNExqeXl6SVlOVkxaTGp4TklQYTJTYVhzdnFSalppbHFsQTdJTXVTcTQ5UVQ0alNkdlEwQmNhM2FWUEM1ZHdDX0VqMWJGaDhzUFlJMGJrcGROWGhsV0ZKZkZWeGNNR3pMOWNNWkhqckF2b3htYkVTMUJFOW15SEJweGZidkcxMkFrUkUyWHpWTTZVcm4yU3NIc2l1MUVQaWVTWURRd2JfZW1XaWx1NlFEZXBoMm44NkxJZFlUb0QwVEtpdkxEOG45c1hCNmFYcG1McFQ3UjFBRnQwTzFReVRxTWx1bm9lbGFoOThNOVZ6Vy1fQnJCMVR4bU8zVHJjU0VzTUJ3QTI0Q01aUHN0S3pTRTVORExuWm5GUE9IRGhFMTU0eW1XTUVYYnFoMDh0VkttNXRFOE1yWUxwek50YUVWMWFlc0ZiMVdibWkza0xiaXVjcmdrdk5lY09pOFpZWC1EYkx3X3pSTFh4LTdVSkg2UkU5Uk5zQjdHa1M3dUNrSzJPSE1mODhsWGJ1dmM4RzhnT1dUc3lRa1dZSXhwaGIxUUJxZHNtdUpXSGdoU3g2bXZmOVdOTEEtMGo3aXh6ZE9zcHpqWDJjRzVtTzBqQkVudm1MeVBfUVozMlFZcnhySWVTMGJfWmp6V1JSOUZRWVlhdm9zamxJcmFBN0tZNDRENHQyZkg3X21XdTd6UmpYUVAwTFV1MlBmVWYtSFducllBbGk2Z1EzMjRjNFU4UmJrT1JOYVhhREpYaF9RVE50Ulc0cFdYTFJ0Ri1xNzRvZHo2S1UyNm53eVhSejF3WGlwZmdlZnd1TVBwVVNIMnZjZmNacEFxZnNOWS1DN0c5TUFEcU14M3A0X2RRV29OejlKcG9SLVpHblhSTzA4eHFPVjBBcWVCN1lMOWdDZVBkeUFyR1hEMG9qcEt4RXlXQW15cE1BWjF5NzlGQktqUG9ZQkVlNHhPNlBCaEFiY0lma1ZWRW9iSi1HdEVZTldqdW1EcWM1ZjlIWlotTFc0V1ZvS0NqRVVuSlBQWmEteVltMWl1R3ZpVnJWY1lENnpjcEh5T1N1S0lnb094OE9rM0gzUFJ1Ujd3MldnUUpUdlRrUEY2UmFnZjloWFVERnNmUUlMQU1mS1JrczQydVZTdFV5TXgwYy1WMnFReEh3Q1A1TDhmVmRveWRmdzRmSzEzMmN6Q0ZMWGpPSUZNSzlMMl9SdFZTNnFFTi1sR2MtNnJiRkFYSWxEQTFwdVZpUlF4cE5YcnVwcDE4Y1p5RlZ0dzZrRWRZdFBidTVFN29MYmVISV90REFmQjNWa2dCemdpNEFFUE8xcTM2SjRIY1RhLmV3bEJIQmdmZXQxRFRzeUFjNmluZnc.EOsJiaSxtRpFTFZWDUIWONAuM6lpMj__Dg59Kuf-hrOlMnP7ePfF6YzXmy9ZRTXW55iB9cxeXQEndomUNxbVii1dPaVOMk0Jb3tFhZuNd8Vg0sKFuC1cR29Q8YkU9_SmGln4FvIWk3zjd6EvfDIFN1Y05odOP_usP3N6oTEjHjkkGqPpNtu8tXJ5pjpoeoA1qADGe1X-UiKwZSTxERC1d_l_btAJaxSNcqgLwWhnM2kOMrqkqpkKO1BInZP0x2VjkOe4jCD2PwniNT1IiEL7aY-jKkjUKtz7688segsgaAcMgu-T_3yUMhLjWuoljNOGqnIJRMt3hrDybVxKRqPI_A";

        // VISA Sandbox
        /*
         * String encryptedData =
         * "eyJhbGciOiJSUzI1NiIsIml2IjoiIiwidGFnIjoiIiwiZW5jIjoiIiwidHlwIjoiSk9TR" +
         * "SIsImtpZCI6IiIsImNoYW5uZWxTZWN1cml0eUNvbnRleHQiOiIifQ.ZXlKaGJHY2lPaUpTVTBFeFh6VWlMQ0pwZGlJNklpSXNJblJoWnlJNklpSXNJbVZ1WXlJNkl"
         * +
         * "rRXhNamhIUTAwaUxDSjBlWEFpT2lKS1QxTkZJaXdpYTJsa0lqb2lWMDlETmxoRk5rdEZXalJXUjBvNVMwZEJWMFV4TXpSVFpuRkhhVGRhTlZCRVNuVkZSWHBLUVZK"
         * +
         * "aVR6SllUVzFYU1NJc0ltTm9ZVzV1Wld4VFpXTjFjbWwwZVVOdmJuUmxlSFFpT2lKU1UwRmZVRXRKSWl3aWFXRjBJam9pTVRVek1EVXlPVEl5TnlKOS5QcFh0dVJPU"
         * +
         * "DdkcnpMd3EtZEIxb2dDb2lZcERiVlBNS1dyN2RmTlpJWGdTZ2VhZW9sNG1FaW1RT2VWTDZlalFvekJPU0daWk9JR0R6ZndDeE04dmFQQ0V2OE5lazdMYkh4LVF2UU"
         * +
         * "5VYVJJa2NEdnl0NWwxUlhCMFJtc0dqV2VKbG9oc2FERjZoWXdnbldCbWtYLTRfOC1lWldSV2lVQ2R3a1dfRVlENU4wNGlHeUllTFFUclFESzd6S0tRc2UzQXFfSnQ"
         * +
         * "tYlRMRVRIN2tWcjNQdFBlcUEwb3FGU0d5YmNTc2dMYU1JejVENE4tMW9JeGY4czNnaTEyOTYxSVZ2ZEpZNlBjbGJQUk8xelQtNmtsRzVSbk5xSm1SLXdPTW55WFlG"
         * +
         * "bVA2MVRPTzRUZ0ZhNEk0dkxETHJGUDI1SkVpcDRTaGlvTFR5a3otSU9zd3JBaDI0MmN3cWcubFFvV0puUkZBM2tFVkFzQS5KR1M2TEpPNHNQSGRvVUo2ZnNxVzBKS"
         * +
         * "V9MWEhXTUd3OEk1RDFKeWx5S0M3b1FIREJGYlBWMTc0M1JlRXRoaUoybEp0LXdqWlNvNzV6RUN5dS1VS0llSXNFdmJGcVhPY2hYaWFZbi1KeDhzSVZxRWpRMWpCVk"
         * +
         * "V2RE0waW9Pbk02V29qVElPNGlmQkdCNUd4d2xHNVVIM2hLb0ZxeXNDTkZSYmpqMlMxSjJ3a1NvV3pSNVZhX2RMejRHM2tiY1VGd0ZHdVQ3T2tfZFBjZ1oxaFktVDR"
         * +
         * "TTURscnVqb1gxeUlLN2UyVXMyZFgxdjFaLWJ5VU5yMkJNTUZ2d1VTV1poRXdNZ2YwQ2RDRi1XOGlScF9wbl9QclA5WEc4dUM0U3U0b2QuWUliM0NMWVB1MFFqbFha"
         * +
         * "dVBPaUk5dw.qbE5FGkBqHrQWFGIMBa_jhW2QlW5NXAJFUSSMrW3vzd3icAI2J-MOMlvaEhhprVFN6w-Gaf9a3oLK7N_4gmrC3_lkOo7qwSuuy07-tqJEctKTTHMtS"
         * +
         * "zgQCuXcxj_0Wf2vNOQI_S1UO-yEZxadnQVwTDZyC5GSbZ_ki6gLyr41TM-vRJCBIzAAkw9nmhV3ys4Xf-F7HKnSO7_e9cDQltEjVZkJlRFDFoPf52PqryKA5FmMRI"
         * +
         * "yzmtl8BCSxAz972ASTCRFCfU6N8gR6KaxY8WOVs77vlcI73t06kdcmLmqUYZC1MPFTUCw5gwzr5nlLnZ91ESbLlDdVWy8VD0ioHta5w";
         */

        // ypylypen + OtpBankIssuerApiKey.SBX
        // String encryptedData =
        // "eyJ0eXAiOiJKT1NFIiwiYWxnIjoiUlMyNTYifQ.ZXlKMGVYQWlPaUpLVDFORklpd2laVzVqSWpvaVFURXlPRWREVFNJc0ltbGhkQ0k2TVRVek1EVTBNekkyTkN3aVlXeG5Jam9pVWxOQk1WODFJaXdpYTJsa0lqb2lSVTFPVVVjeVJqWlBXakJWVlRGWVFqSklOMGN4TTB0alpHWlVia1ZEWlZwV1NHNXZlbTVxTWtaRWMyMWhaMlIxVVNKOS5HclFTUnhzbTJzYnVLWEh5bFkyU2xRX082aXVrVU9jeDUyS2w1N1JZeW1CS2VjeWk4MG93S3c2dGJVa3ZYS0ZFUF9Mc05wZWdyaTdsLTlhaWZRdFNmR25BZHJOWDVobEhjYzRpRW1kRGUycWpQaDQ0NDFNemRsbzBvU1RJVUluLXFlclgzc2ZabVVHajYycWVYbnJ6cUJzU1pYS3JieUlRbktmYzR1eTRJYjBoX0h2bExZeE93dTd0WlZDY3Z3UF9ENHlvTG1mWEZHNmNmaGozN2VYMEFCUEQyS0IwTVRZUV9RZ1ZNZlNGTGNrQkpvemRzQTB2eXowOEE4R2E3SDZCRFNrOEJQQXcxTm9WVVN1Nkw1XzcwWW52dVBpOFRQVTI4eElSb0RaaEFWdmVfY1l5dGFKNG5USWZPT1oybUpUMGlFWlJSTDRUd3Fvak1DajZYMUpHWWcuc3dRT2FsV3drUFlhQmdGZS5OOHlPTjQ1QTgwTi1xSEpNb053Q2lZTnRGS1NFb1NrM1ZVYWVpTmxqWUxQQV9uSHkwS1JlRXpMa2lTOFRmOFpPY1EzVUN1Rll2NXM2RjZkLXJvbFdVZzlOYlZ6WlNiQWdXUmg2TmFqTk9Od1JseUdGUU1SWU14NXZSVllMN0VVVk9JX3ZTbk9nYmozN3FjcjNhYlJJT1dYdXBISXZFcHZFR3cwcnlhZ1ZQQ09VVFlyeEZ4UW4wdHZtNXNDMDNONXdEellfQ2NsSHROQVk4SVIwR3FpVXNPdlhsRkhLWmZsQmJJdUZnVl8wNnY0akx0VnpibkNmM2EySVZlRmRpWTI0Wk5NZkFURUFkTEgxQXlVWll5ODZuV001MC03MlVQTzdXaHJYUmt1MXlkb1hSMnBVMEJnNURQZ2JQTC05RWNNZ1lYZXFZZWtQcnFZdGxZajFWU2w1eTE4TlhfaW9Jd3d2Sm9vbDZhb1JKX1d6dzdnOW5LbnhBQWcuZ1M1aFloNjRWRV9wZ19RYUxlWnRKQQ.b0nm-zsQnokmlBomv-1gggfGKAhuNrVXqld1zN-Uudu8C2e07q8nm7qFiNJcsD_bFFHhMGX04_LJw8h24XE7GPe3iZaFZxuNpXo9AP7uzrlZdyKDWClhJqBx_numcMmr5E9MUVGOF9V2TQ3xSiOXJS6URzhxvqMsiPjQgaD4MvRrX_GpajrsVRAFKcTrfF3Zrs5SILHGzwLgKKlaEPeGQbYOIZs5Cef74HkaWrGNfsQwjR8uExfppA-EdrkemgZwhmLn9OM-cOeUymNVs9S3P5-FfLvisXdQJ--YwsM0x7YxhMLfUuC_kwEZqbot_1ER4tZKOhD5fczvua-Bc2i3FQ";

        // my
        String encryptedData = staticSignedEncryptedData;

        String clearedPem = pemEncodedCertificate.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "").replace(" ", "");

        byte[] asn1bytes = Base64.getDecoder().decode(clearedPem);

        KeyHandle cert = engine.rsaKeyAlg().createX509Certificate(asn1bytes);

        RsaKeyPublicData rsakpd = RsaKeyUtil.getRsaKeyPublicData(session, cert);
        RSAPublicKeySpec rsaPubKeySpec = new RSAPublicKeySpec(new BigInteger(1, rsakpd.getModulus()),
                new BigInteger(1, rsakpd.getPublicExponent()));
        RSAPublicKey rsaPubKey = (RSAPublicKey) KeyFactory.getInstance("RSA", Security.getProvider("SunRsaSign"))
                .generatePublic(rsaPubKeySpec);

        String[] parts = encryptedData.split("\\.");

        if (parts.length != 3) {
            throw new TokenRuntimeException("Invalid JWS format: must consist of 3 parts delimited by dots");
        }

        byte[] jwsSignature = Base64.getUrlDecoder().decode(parts[2]);

        Signature signature = Signature.getInstance("SHA256withRSA", "SunRsaSign");

        signature.initVerify(rsaPubKey);

        signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));

        if (!signature.verify(jwsSignature)) {
            throw new TokenRuntimeException("JWS verification failed");
        }

        KeyHandle dk = SymmetricKeyUtil.generateKey(session, KEY_TYPE.DES3);
        KeyHandle privKey = engine.rsaKeyAlg().unwrapKey_LMK(HexUtil.hexToBytes(wrappedKey));
        byte[] privKeyUnderDk = RsaKeyUtil.wrapKey_DES3(session, privKey, dk);
        byte[] privKeyBytes = SymmetricKeyUtil.decrypt(session, dk, KEY_TYPE.DES3, privKeyUnderDk);
        RSAPrivateKeySpec rsaPrivKeySpec = RsaKeyUtil.buildPrivateKeySpec(privKeyBytes);

        PrivateKey rsaPrivKey = KeyFactory.getInstance("RSA", Security.getProvider("SunRsaSign"))
                .generatePrivate(rsaPrivKeySpec);

        String jwe = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);

        parts = jwe.split("\\.");

        if (parts.length != 5) {
            throw new TokenRuntimeException("Invalid JWE format: must consist of 5 parts delimited by dots");
        }

        System.out.println(
                "JWE header: " + new String(Base64.getUrlDecoder().decode(parts[0].getBytes(StandardCharsets.UTF_8))));

        byte[] encRsk = Base64.getUrlDecoder().decode(parts[1].getBytes(StandardCharsets.UTF_8));

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");

        cipher.init(Cipher.DECRYPT_MODE, rsaPrivKey);

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

    private void decryptVtsIapi3EncryptedData(CryptoEngine engine, HsmSession session) throws InvalidKeySpecException,
            NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ParseException, JOSEException {
        // IssuerAPI_JWS_CERT.SANDBOX.2.pem
        // String pemEncodedCertificate = "-----BEGIN
        // CERTIFICATE-----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-----END
        // CERTIFICATE-----";

        // test alfa and otp
        String pemEncodedCertificate = "-----BEGIN CERTIFICATE-----MIIDOjCCAiICCQDTWQKEAhMaBDANBgkqhkiG9w0BAQsFADBfMQswCQYDVQQGEwJVQTEOMAwGA1UECAwFU3RhdGUxDTALBgNVBAcMBENpdHkxEDAOBgNVBAoMB0NvbXBhbnkxCzAJBgNVBAsMAk9VMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMTgwMTI1MTAwMzMxWhcNMTkwMTI1MTAwMzMxWjBfMQswCQYDVQQGEwJVQTEOMAwGA1UECAwFU3RhdGUxDTALBgNVBAcMBENpdHkxEDAOBgNVBAoMB0NvbXBhbnkxCzAJBgNVBAsMAk9VMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDE1C5HFBuf3e7beceeSoze9jutDc4EohsRq+zRGY22afStASj2Sy7gWO9/J6QDxih/EDy8X0EiIQAjcm1QB2Y4odlMFyAZGozyC2/0A+ObDzCmi34D5+ucMyReg1B3X795msg1r46fB0MZ92aAosRGfQQ/IZB+whFmAMAZmp63yN1vBPznYA3PmU/UdB0bf+9pkI9UtV2JvADdrMIhjE0/iXTr0koH9h7wqADCZ5Csgez2rpeChIHtphiVGa5bgqm3kCa6FIOt8Or9EkxM1xbOLtTUFkNzWCwHLTllaeFirufaYFXAF+ZW0LthAhVH0hdW7kLxDb9+G+B7ekCgcOjRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEVffmmLryXA6Ydv3ZWvcB5y7yMfHSdx7VKM1+cWSuoqkr9xvLb3/1q9/Pa2tXkaHqLlz8WQ/u2FBD6n2UqyodBfn2db7dqzHVYLIQiHD/WEmvzH31R6sdPnQCHxZEcLsyiicvBUN3b0pfKxMsDEsbLlJpUe/XVR8V8EQwQOBCq9FcqeMvQtChFgbdp12c2/YBAeOZ0P0Fj9TQc3UHcWz705IKLaXyz0vavJObZ+JaeoT+rBT3sRSgBEoZv+Izkh3hHRGrxGkFT6/ExG05BR8+0A4Bc06bshrkzQ7NH7VXb05T7yXV2rh+qcILKnzhvMtMxl6ZU/znB8LxD2jr/kgho=-----END CERTIFICATE-----";

        // my
        // String pemEncodedCertificate = "-----BEGIN
        // CERTIFICATE-----MIIDizCCAnOgAwIBAgIJAI9bAW3jvs8eMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNVBAYTAlVBMQ0wCwYDVQQIDARLeWl2MQ0wCwYDVQQHDARLeWl2MREwDwYDVQQKDAhDVFMgTHRkLjEPMA0GA1UECwwGRGV2T3BzMQswCQYDVQQDDAJESTAeFw0xODAzMjIwNjIyNTJaFw0yODAzMTkwNjIyNTJaMFwxCzAJBgNVBAYTAlVBMQ0wCwYDVQQIDARLeWl2MQ0wCwYDVQQHDARLeWl2MREwDwYDVQQKDAhDVFMgTHRkLjEPMA0GA1UECwwGRGV2T3BzMQswCQYDVQQDDAJESTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPMge53NcDh3jAN2qGJ5uTHeLnuQHPFcAwom67LnOvNTtl9k02tGhq7WNUTeUj1YAmG5WRmyHQRSOKjQ43OV/tB1fqbslxdQTkax5Sg0XhZ0/fzHd4oZ9YRKfeCJfMyuZwWb6+pOARQwYaZcUmxZMeEpThOtQLWL7Pkj+cZmAmlt7vWE5iZLRW9ZVRF8r0EcnJDGdF+hCDaqEq2w0HUsE412M2NE31Vu5sLc3Gz+NmMrG8uARUcxv9AFFKhrSW3ULmTBE1SKdUXDm3/IeMlVW/ppjvSMMkhBVEhVuSacMqJxST1KXUf8vMD4p4HyiGDl0TEiNeHVZUzvPmCo1CKfGikCAwEAAaNQME4wHQYDVR0OBBYEFLCCnmdxUCtVuuPYxniGpDZQGuv5MB8GA1UdIwQYMBaAFLCCnmdxUCtVuuPYxniGpDZQGuv5MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFrBFHRJ70PcaeMRrfTZwadGZ1yP2e3jtoFlnzmRjSTgWajiaqxFzZa5h8f4sxbJLXrumFHQXP5/aN7X0hZTB/Zlrkt8chWEDLlU9ZVK7TH9iaoHOTpvwHoFsDpotmsH/PISLUx1RY1z2hJmL0kL4gAT3OMKf9UwOebG5+dYXDqsO40MUtZCRNWl1DSl/PusBfkgWgW9z3ublGYuzuDR6ruT2WOPvmkFH7JQfOF8SZV9h0ZdTPcr6zfFegUHbK7gILMh63zvQ+blcEmUhm63BZcBcykT9Bm7ca80gkyOMNo/BM9NqqAeYELuEL5sibw9q7Cnl6BnY8Ogcd5JGJgdlZ4=-----END
        // CERTIFICATE-----";

        // ypylypen
        // String pemEncodedCertificate = "-----BEGIN
        // CERTIFICATE-----MIIEszCCA5ugAwIBAgIJAOsA/5RhU4DTMA0GCSqGSIb3DQEBBQUAMIGXMQswCQYDVQQGEwJVQTETMBEGA1UECBMKU29tZS1TdGF0ZTENMAsGA1UEBxMES3lpdjENMAsGA1UEChMEVmlzYTEYMBYGA1UECxMPVlRTIEludGVncmF0aW9uMRkwFwYDVQQDExBZZXZoZW4gUHlseXBlbmtvMSAwHgYJKoZIhvcNAQkBFhF5cHlseXBlbkB2aXNhLmNvbTAeFw0xODA2MjcxMzUxMjFaFw0yODA2MjQxMzUxMjFaMIGXMQswCQYDVQQGEwJVQTETMBEGA1UECBMKU29tZS1TdGF0ZTENMAsGA1UEBxMES3lpdjENMAsGA1UEChMEVmlzYTEYMBYGA1UECxMPVlRTIEludGVncmF0aW9uMRkwFwYDVQQDExBZZXZoZW4gUHlseXBlbmtvMSAwHgYJKoZIhvcNAQkBFhF5cHlseXBlbkB2aXNhLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN4n1L+XP+1seNuX8yfhLLDFJ4ry3OJwjh1IVfukH1PASt3anSuxBHLV+Bpqnq/1sirMhkSA6svKbKLIoXrn5Dazp/kcGBOHt1OgtsRMoF3TYGqU1pLQUQg4OqoYZG7Gc/qGzcqbSQWZLcjWrhpPQix+3exeKIe6KkxYG3LY1+6S1/LGOZrqOsQB2Ow8DIeT6YbUdYazSYix/heW4LdCDnB4WP1wSuVKwoctbuelsIpOy66xxD6T/YhkFpI80750CRLwRmlMLfbgfvfFk8OYIaVbQjbyd7Yma9NMyF5nQuf4zSREDE39P8a3bu3Tt1XyN6neYtT9fe4MSaNUwHl4sd0CAwEAAaOB/zCB/DAdBgNVHQ4EFgQUvhv4YxrWS7xAjSCGfrbtB17V9pgwgcwGA1UdIwSBxDCBwYAUvhv4YxrWS7xAjSCGfrbtB17V9pihgZ2kgZowgZcxCzAJBgNVBAYTAlVBMRMwEQYDVQQIEwpTb21lLVN0YXRlMQ0wCwYDVQQHEwRLeWl2MQ0wCwYDVQQKEwRWaXNhMRgwFgYDVQQLEw9WVFMgSW50ZWdyYXRpb24xGTAXBgNVBAMTEFlldmhlbiBQeWx5cGVua28xIDAeBgkqhkiG9w0BCQEWEXlweWx5cGVuQHZpc2EuY29tggkA6wD/lGFTgNMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEA3eKDaJaP0zZ1OSVzYXB1KDZjRHWQrqEE3yiCOcPOzQJKa6uXviYRokjfqLdLcewjyoe6dbhxh+6iYBXjSCeGUo0R3T+dgnB5g4PtRmLBP8IMjvb7kBPkCRP6cjUBKJ4BKZII2tTjWGwKD2s0eSp+r6ynjsEzuosi6lBukzewGwBIF5FE82b7InJNNZsKrgmWyy7KhGTNFgzGbM3vMGBFgzdn22fbBGmXLaH2SPOV0gSx0zNFXaQvB8BC1uSpP+UMjqJtWiLiZHsdt08KK029OPI56rcpjFCBrZq2opdq2d7x+dd/F4+/ZxvhJq26BlH8U0bCGhxtJyM9fycDYJtaIA==-----END
        // CERTIFICATE-----";

        // my
        // String wrappedKey =
        // "EF44A6D278BF166A50D2B633B575BA62FF7992ECBE94CEFF470213300CA5B2AC9504C40369DF7B0B57EF6AA8DAED707C874B58E3358EA295237B51BE9EB3A64E8173469F3E52A74337354800D5264A2ECA2A73AA424B0393A4735E6D3AAD58DC3EB85F89DF885038C5155DA20FEEE6A90AE49DB9D3D5B2564ED261622550326FF8402496FD8BD4CE1E5FACE48087BC4507C46C5D2243928B20E339A9599D67444EA2A879B916346B2A58800F8919B8896B452BD996FF697659094E20FCBF73B091D9A0641DA31F37EB2A58D76E1B096BD34F6405259388FFF8FE86BFC647A0C1627797AF3F7BF9097E067AAB917D2B0544E541BBF0DE11D02D348619F7D54F86D0B206DA7D838FED8A46364151D92F234D931B78C7878486A55D4B7AC3EB67DAC2D96EC2C44035382647759AE8021645D9B7B0335EFD3CA1F079BDEC1229395B6BD2BF5BC7630AFD00E23E9059DA8D2C93B4BDC023C3A9FC4D66F1FE563D6E8C21ACFFB13F5B38F6F4F88EF2D10FDD8553DE800C9439CE19128CAC4406527404919B080B6A041930D9D3034073FBDF7D71F1B8DEED85CBCFD5EC88FF1DD00260526C6D0C974863CC3BEFF2F6BC99E0F42B68314149A9845629922FA9A3D51A7B53F96EB4C370118278F1A4F69ACB0F517F8289DDD32C912FD2B94782BD0D116AAA599470736D5DEF2A4F542BA40D1AF4A04897BC8641A416B8EA9F2566A7D663ECC9EB003D913510D4DFCFCC89A060A6274DF45FF69F9CACFD50B712E4B735AAE48865FF8853A93491B4B2A2B7B0FD316D5737EF0B62AFAAA628EA57CAC42F965B9C8AB3952C024C6ABD8A5176C36B32679A7B8AD2DC97DF76746D6495AF1CC5727F394D452C428C02480DC8A6D19E07EEFB8937E09E2ECDD14D9805517F91FB3B27502B53FF41C60926255130DA97B278B14A1BB685744A3CCC241B8ADAC2726167D216F112C8D97BF39138B5F55ADC5B83B31620C6D996173A2C0887B288ED5001C8F5F5388B1EE450607788CB2619961E3571EA25E342B6895BC87B63F71BCBE0AAD24281FF21DB2C635DA9141AB920FDB0619E6D86BF35E71C7A0B5EF15D283305B0533D75369435D778AD121752393936B304A4AC7A4494105EF8D90025542F93F7C2D4634846DA7670E39D87E45D5770AC3F7EB271B3537D13B38481976FBD7C1E8C9B9242534EDE4F452CA48CA9A16743246875311F35285A5A047F230B1548C30D2C02F41D40AD0BA1CB9FEE8A5ADCA0B1E59DD3E9E8B154D19BD76F93AC8BEF9AD8D157069C8C06B76A06AB1CE969CFF788B60E960A5282CD81EEB5602235426348835E6BFF283900E2F25430F62472329A850BB12066CB7FBF10E39BB44E61A6DE2C9F148A8141A508AB6C4ED870442D9163B18F0174DF0D59639490A5029B9C4378899F0E7C1319834AC840BA282C074FBF36043CB552BC6E073881CED671DD2C5B6F36E71326B58F101F64D5A584B5A10EC177B271367FBBC29F42989BD6A6FBCE04C11A1E948A0A853F937679339041010D1DBF53E487EBB553EE3701FE9CE5DCB68253BA8519C048B1E8892272DE2E31D997B52A2BA431272A27127C5018C13DDD24C649ACA5848DF0D675108979BB03794BA40794950469FA0D335C2E09B95C09FD8C8E6127BEA6E38C3CBDC4535B2C3A13B29513C3A01C3A814E9CBF34FF2D0FDCD04BF0FA558876CE7D3499EDF3FCEDC4AA3066B26972A37CAA6B98E96333DADE2F4E88D458CEDA";

        // OtpBankIssuerApiKey.SBX
        String wrappedKey = "AE5CC0A0D072BCEF8C2765F34626839AB70522D09C11DA5C0B04AEAB46078BBDED2224C08E4E2899618795ED7A7350AB2A68175AF6F980AD589C7A644B53AF7BDBBFF8F2281784C7F69B278F8F32FD427631DDFE63812584CB425AD3CBF4E86476A95A65932C680D34FFF42B4E8EC6644A72262D2F8A8D77E3754A1B339B69EDAE08315473967F85BCB4574F57121DD11348F0E46D62404AC8BA1FF81EC09CC8DBDBDCEA7C1B50FDE8F28ECB826AE521294845EE485251DFC58284FDFB9B9FC2E7CE8DB8C3E385C43C3653EF655711C80B1282BD9479CB2648F68FC63BF30647664C4AAE4D857C6E1C78E0FF3473090CCF79CD236671343A9F8B209CE1807C1FE94331A1D39A6605D2CC3A52A1ED1AC98159CC33FA40F1CA6D0702F36B9A251517FABA31DC9CDC2D3D285E3C8BE08F172E844E750282DD9A77101A83F33CC18E8BCC7E4FA953FFBB8475BDABD1BD6A6BE8453BB886EEC31835183C437AB9BE97DAA481ABD42E7DEDEC6B2BAFDD794882FB9D06CA7CE87CE2777C00ABFB7E9BAC8CF434AFA1BAB1241BB541CDEBD42E7830E166AD1F7049FF1E4ED11C499B4D9314B9AF300167208E333057642306BCA9F91A2323580DC6419EFB646CD5AA015A6B956E98B2C5F7F47C6D15D796098A1A3C4E9DCE4CDED388277BE2897441BEBF081EB5C89FBE590206379CF6BA32006B602F03E4366E1BEF6BBD3865EEFEFB1B0218B9B1578DF3D11F8A822AF48807B946DE4C653D024778FD42703DA58AE215189ADFE516130338CF523BCBB1E5D15E1DB046BB534E1B857DECF93A954629B5D69E85C698DA9C6960180C892A8911CF9538B4584B19589DE9F10307D167B021DD4638D07820D73A2809012779705542BF90384D220E690DFC4E905A46644FE2E7A681D4760190FF44575535F8DDC661501E2F6F0C2160B1B47C4E2CE989D80B806290A418274FA1BA701BA677DA3651B89AE9500234F02EBE5E17CBC6395F908B0ED54EBD036C872C8F6E2AF5695FC685729C08DC5D4280CD08FAAA325E3AE160A7F8F58CFDA63732EBD99DF6D96921F775781D5D859074C5975473F8C82D60C6BE1021588B410637F03CF86BCA471AA173C9ADBD6B0111D6AD53B0828F636BCEE83EF970799D6964C1E552A5E0FDE259FB9F70C0718916D6F2403B7F6CA12D40F90EA4077DEEB58579A21968100E4266DF363CEFDAEA5F7DA575FAA8C8D8C92B4890B3D445ABA8F2612595B86757A9E9DA055F8769681AFEE8925027CFA4E912C128DBA1CC42ACD10D0D0AB71273EB42600C9444DFCD42600D462F19D3C643E57A2F5C1AC450A80705398B0890D3058CA7B3364D8ACB8DE3F1CB70E578A6E45052AF0039663E935FCCFACA6A372AFCA8703F4EF2F3ABF14F10A9C176A8ACAA12B54BC7289EA163A799596E04CAEA3BF8113B638DC1630E818C60CC6360BD993FF25B124B67B7781DE1231B7B3EC995A038E787DC59492A82640C1B2639BC9373B3A3430A38F77122DBDCAC62810820A12BA5678C9D1D1B0F96A186D2A498829804F3DED3E9C6FEBF083B4DBE6D074CE0DBB605EAE152146CB7D6455B722C294B29FD3B90499A0EAC4F2D4E1AE47C8068CF7F481E6AD6D36D57856E771E21B35CFBE5421B282247CD14ED79B6A669310B29EB4E9B250503BC3FBFBBADB1538A01890D82AA0EB3A6FD2232580E48E91FFEFE8AEEEF733A2F436562153DEEE46C";

        /*
         * String encryptedData =
         * "eyJhbGciOiJSUzI1NiIsIml2IjoiIiwidGFnIjoiIiwiZW5jIjoiIiwidHlwIjoiSk9TRSIsImtpZCI6IiIsImNoYW5uZWxTZWN1cml0eUNvbnRleHQiOiIifQ.ZXlKaGJHY2lPaUpTVTBFeFh6VWlMQ0pwZGlJNklpSXNJblJoWnlJNklpSXN"
         * +
         * "JbVZ1WXlJNklrRXhNamhIUTAwaUxDSjBlWEFpT2lKS1QxTkZJaXdpYTJsa0lqb2lSVTFPVVVjeVJqWlBXakJWVlRGWVFqSklOMGN4TTB0alpHWlVia1ZEWlZwV1NHNXZlbTVxTWtaRWMyMWhaMlIxVVNJc0ltTm9ZVzV1Wld4VFpXTjFjbWwwZVVOdmJuUmxlSFFpT"
         * +
         * "2lKU1UwRmZVRXRKSWl3aWFXRjBJam9pTVRVeE9UQXpORFUxTnlKOS5OakRuTS1DS0l0TldKMWlSdDhCb3NmMUg5LWRUN2VnTl83X0dQT0NGNjctdi1McGl2eVB6eEI4NzV6Y09QckJkZWlZbnVjSHRhNDZFN1d3UTBfZ2RiUjJ5eE5HZjd0Mkd6YlNFdUhtdUtSNll"
         * +
         * "EZFFfMHhfYkZfaU5HLW5PRDhDNmg5SG81RmNuakh4MThiLXdxUXNMY0ZPQ2lubmRld0xTVUxrZGZaTlJyalNqUi1uRHRybWNzOEZ0UUZMSnNleFV5TDQ4OWF6SlFsSU44a1RBNng4MkRaTHYzV1F6QldaLTJuVURvcEp3RTM2bTZuaUM3REJBbmpTd1hkQ2s0eTFLa"
         * +
         * "XZ4S1ZNbVlMRkQ3VEFxMXdBME1xNjE0cnVMbm5WampwZHkzZUx5MHNfUndySmFzNVNOQ2QxV2RuT3hkZkFfcHB6UC0yNE9yX2dLNDBDU2tmUU5NekEuTnh0c2dlSGNELTFqeWt2US5ncVphNS1sZGY0STZiMTY0c2dwWURhaG9iTXpKQmk2ZWtYMjdWMEJBcTQtS2l"
         * +
         * "IbnFGSnFfcHZrZWZ2bEZtVGk2MHhBeVBTT1ZvYmE2cm5qQTQyMzhkbVI5ZVNfZ25sNjJEbWE2a3hvVlZSUEh6eFlTWFBuRmtuMnZuYWtuWHRlczhZMzJpa3ViZWh6U3kyWUllUDV6Zkp2ZjVsV1YxTEF6WGJoT1dWTi1zdmdldlRHNFAtcVExWTVYLUNDTUFhRXNPT"
         * +
         * "UNIbUZDdG51MklyNHVCcUx3Uk5ZYU9SaTR0R2wtMmhsdUhkdF9mWWd6dnFqejdjalppSmY0RzNvMDdVMUhUZ3JtTDR3XzFidy5XWVNwTnFIMTNOMTlXNkpIZk1oTXRR.iOd6hhB5rxa0y6vymGV6AHX_Xxigugsop_NyaC92TDjomEJsyKE4eq-Dmwh_utfzk3IIyW"
         * +
         * "NpyydGDpsalVgliHcGYSyS2Gl2OMl0mBgjT8MPnKrLSnHG198dMP6an-ClWM6xjawHIAwI1_fUsGCB5Xa9KWtqOvPNDH9LfBB2YJ_g9aNmX5mSqu9y_R9eZ8HRb-OPwH_rVPOJvfmVe7WEQSbU8uD7uVro2-WW-nU15WtxlWkCS3Z8YPbBY_Wl08OToNRab2_AkBT6"
         * +
         * "_komCz0Q7qnMCSQ8S1PHliBZV61jsQZJOw3_jFB7OTORTtM_V_SNBc0G61E7t0K9pr_iIY6sBQ";
         */

        // String encryptedData =
        // "eyJ0eXAiOiJKT1NFIiwiYWxnIjoiUlMyNTYifQ.ZXlKcmFXUWlPaUkzUjBoWFN6TlJUMGhHU0VrMU9UWldRbGRTUlRFeFVXcFVWekV5VEdOVU4xVk5MVkpUUW05UFEzZEdkWHBTUW1KVklpd2lkSGx3SWpvaVNrOVRSU0lzSW5SaFp5STZJaUlzSW1Ob1lXNXVaV3hUWldOMWNtbDBlVU52Ym5SbGVIUWlPaUpTVTBGZlVFdEpJaXdpWlc1aklqb2lRVEV5T0VkRFRTSXNJbWxoZENJNklqRTFNakUzTURVME16WWlMQ0poYkdjaU9pSlNVMEV4WHpVaUxDSnBkaUk2SWlKOS5SNEhydDFRbEhzZWhyblY3cjNveUtqOHNUSTNiOVRVOWh2dWpJT0E5ZWxaV2NMWHRYMWVGSlpreVVKMzRVTWVyaDA1ZDc2TXZmamhzWWIxbnVkTWM0dmFXdjlqdXRWa0dOWFhYS21EY1hPcDhpWnN4LTM2a0pRandIbjZmTFV0aVE0OENadHQ4eWduV3VqYmlod1Zpd21XV2pWWHVrNXdqNXdBTlFSbUl3LXhGd2JVclRPUkNBSEFZR1pjQ1dJN29wUVVuNzNaT3o4cElkOEFNV0R6QllrYThkZ3NyaC1QeF84THd3cGdycG10ZXAtcHkwOHBKNkt0YlEtLW14Y040enZ0RGpzakpPeEROdHE4MjhqQUdfdjRFazdGWjR4T25CMmFYeGIwd0RkRXA5M3otM2Fkeng5NzRKS1ppbTNiUmpCVVBncGlJWUFYT25FdmdNVndLMncuY29CV2J6TDZJLWRVMjY2Zi5weVJUMlJpaWwwVzhyQnd3N1ByaS1uUG1pelhZNGJNR0UwRmluZW9vejQyUmlvTlE1ZWZaUEd6alJELXJGNTN1WDVTN2VXWUFDMlBRMEtDckhHZnk5b0JTZzRaNzNSeGlXQUYwdVRsVFRnVXdBSHNlMm5wMDJEV18wWGswWUs5Y1dsa3NTenF6ZjRlMWdhR1dEMnExMC1rMzA0MEptTzV5NjkzR0VFNWhrMkN2WnFMRVBOYjhxWlNrTGdrbUVxbG5GZm5feFZ0X0R0ZTNhX2IwWndFczE0cjV1YjlodTRnUkNqY1J1a1c0Y09TcHJJVVNaQ3NJMkxxYXo5bE1wLUstOGk5ckp6MERHS09UOE8yYWZoUkR1bk5XUjFKdmdrdjR4Z051VmpzX1dFdExmaFlrbDdHdmMycWo2MnJWSDNUTU1iYkRBMTZIN2Y5RXFNb2h1Y1VMZU1lbXM4WG83YTF6bjItYTJBZTZlYjZUeGtXZVNEUWczdlBxTDZUWHZjRXBQbFRrWTMtd2RwNGdHeGZQcmRKNFlxdkU2WEFRclh0R0xjY0sxY2V2YUZXanl1M2lRNktEaEctanR6ajZENEpHWHpBa3ByWmRtOTlwMXdCbE5FM0JoSFVvVTB1N3J4ZVZzNlRRSDhwLUlBQ25tcE0ya2ZHaGQzNWR4V1lVTGo5RTNUYXZsX3FJbF9DZk9fS25zX0doa2ktdlJuTWlMWEtBN2wxaXQ2dGVabWxzS0RHbUZzVzc3RFd3YURHQ2ZONEI0OWRkNWxEM0hFbmVpcVZNb1Y2dU9nZTFhSjUzcVUyZGl4TmUzNUlIWElBMC1oSW9lUG1RNU4zYndwZWEzMUp4eXZyM3RyMDJnNEowejJ5NkE2bXRYdkhkQ18zMXVkX1A3RjMwalVWS1MxcWZPTE1OTkJuWGN6NVJqc2Y1ZW41cUpCaVNXV3JRbkg3TDNaeTYxaXNPZlN5cWtHVDZZRWVFVGhDMC1TZ0ZNUWVaS0ZxNlZVZXJDNUg0Y3RnQmN5OHRhV2dycGRWZmRkVk0tT0lBenpGcm9oNTNHVG5TNExqeXl6SVlOVkxaTGp4TklQYTJTYVhzdnFSalppbHFsQTdJTXVTcTQ5UVQ0alNkdlEwQmNhM2FWUEM1ZHdDX0VqMWJGaDhzUFlJMGJrcGROWGhsV0ZKZkZWeGNNR3pMOWNNWkhqckF2b3htYkVTMUJFOW15SEJweGZidkcxMkFrUkUyWHpWTTZVcm4yU3NIc2l1MUVQaWVTWURRd2JfZW1XaWx1NlFEZXBoMm44NkxJZFlUb0QwVEtpdkxEOG45c1hCNmFYcG1McFQ3UjFBRnQwTzFReVRxTWx1bm9lbGFoOThNOVZ6Vy1fQnJCMVR4bU8zVHJjU0VzTUJ3QTI0Q01aUHN0S3pTRTVORExuWm5GUE9IRGhFMTU0eW1XTUVYYnFoMDh0VkttNXRFOE1yWUxwek50YUVWMWFlc0ZiMVdibWkza0xiaXVjcmdrdk5lY09pOFpZWC1EYkx3X3pSTFh4LTdVSkg2UkU5Uk5zQjdHa1M3dUNrSzJPSE1mODhsWGJ1dmM4RzhnT1dUc3lRa1dZSXhwaGIxUUJxZHNtdUpXSGdoU3g2bXZmOVdOTEEtMGo3aXh6ZE9zcHpqWDJjRzVtTzBqQkVudm1MeVBfUVozMlFZcnhySWVTMGJfWmp6V1JSOUZRWVlhdm9zamxJcmFBN0tZNDRENHQyZkg3X21XdTd6UmpYUVAwTFV1MlBmVWYtSFducllBbGk2Z1EzMjRjNFU4UmJrT1JOYVhhREpYaF9RVE50Ulc0cFdYTFJ0Ri1xNzRvZHo2S1UyNm53eVhSejF3WGlwZmdlZnd1TVBwVVNIMnZjZmNacEFxZnNOWS1DN0c5TUFEcU14M3A0X2RRV29OejlKcG9SLVpHblhSTzA4eHFPVjBBcWVCN1lMOWdDZVBkeUFyR1hEMG9qcEt4RXlXQW15cE1BWjF5NzlGQktqUG9ZQkVlNHhPNlBCaEFiY0lma1ZWRW9iSi1HdEVZTldqdW1EcWM1ZjlIWlotTFc0V1ZvS0NqRVVuSlBQWmEteVltMWl1R3ZpVnJWY1lENnpjcEh5T1N1S0lnb094OE9rM0gzUFJ1Ujd3MldnUUpUdlRrUEY2UmFnZjloWFVERnNmUUlMQU1mS1JrczQydVZTdFV5TXgwYy1WMnFReEh3Q1A1TDhmVmRveWRmdzRmSzEzMmN6Q0ZMWGpPSUZNSzlMMl9SdFZTNnFFTi1sR2MtNnJiRkFYSWxEQTFwdVZpUlF4cE5YcnVwcDE4Y1p5RlZ0dzZrRWRZdFBidTVFN29MYmVISV90REFmQjNWa2dCemdpNEFFUE8xcTM2SjRIY1RhLmV3bEJIQmdmZXQxRFRzeUFjNmluZnc.EOsJiaSxtRpFTFZWDUIWONAuM6lpMj__Dg59Kuf-hrOlMnP7ePfF6YzXmy9ZRTXW55iB9cxeXQEndomUNxbVii1dPaVOMk0Jb3tFhZuNd8Vg0sKFuC1cR29Q8YkU9_SmGln4FvIWk3zjd6EvfDIFN1Y05odOP_usP3N6oTEjHjkkGqPpNtu8tXJ5pjpoeoA1qADGe1X-UiKwZSTxERC1d_l_btAJaxSNcqgLwWhnM2kOMrqkqpkKO1BInZP0x2VjkOe4jCD2PwniNT1IiEL7aY-jKkjUKtz7688segsgaAcMgu-T_3yUMhLjWuoljNOGqnIJRMt3hrDybVxKRqPI_A";

        // VISA Sandbox
        /*
         * String encryptedData =
         * "eyJhbGciOiJSUzI1NiIsIml2IjoiIiwidGFnIjoiIiwiZW5jIjoiIiwidHlwIjoiSk9TR" +
         * "SIsImtpZCI6IiIsImNoYW5uZWxTZWN1cml0eUNvbnRleHQiOiIifQ.ZXlKaGJHY2lPaUpTVTBFeFh6VWlMQ0pwZGlJNklpSXNJblJoWnlJNklpSXNJbVZ1WXlJNkl"
         * +
         * "rRXhNamhIUTAwaUxDSjBlWEFpT2lKS1QxTkZJaXdpYTJsa0lqb2lWMDlETmxoRk5rdEZXalJXUjBvNVMwZEJWMFV4TXpSVFpuRkhhVGRhTlZCRVNuVkZSWHBLUVZK"
         * +
         * "aVR6SllUVzFYU1NJc0ltTm9ZVzV1Wld4VFpXTjFjbWwwZVVOdmJuUmxlSFFpT2lKU1UwRmZVRXRKSWl3aWFXRjBJam9pTVRVek1EVXlPVEl5TnlKOS5QcFh0dVJPU"
         * +
         * "DdkcnpMd3EtZEIxb2dDb2lZcERiVlBNS1dyN2RmTlpJWGdTZ2VhZW9sNG1FaW1RT2VWTDZlalFvekJPU0daWk9JR0R6ZndDeE04dmFQQ0V2OE5lazdMYkh4LVF2UU"
         * +
         * "5VYVJJa2NEdnl0NWwxUlhCMFJtc0dqV2VKbG9oc2FERjZoWXdnbldCbWtYLTRfOC1lWldSV2lVQ2R3a1dfRVlENU4wNGlHeUllTFFUclFESzd6S0tRc2UzQXFfSnQ"
         * +
         * "tYlRMRVRIN2tWcjNQdFBlcUEwb3FGU0d5YmNTc2dMYU1JejVENE4tMW9JeGY4czNnaTEyOTYxSVZ2ZEpZNlBjbGJQUk8xelQtNmtsRzVSbk5xSm1SLXdPTW55WFlG"
         * +
         * "bVA2MVRPTzRUZ0ZhNEk0dkxETHJGUDI1SkVpcDRTaGlvTFR5a3otSU9zd3JBaDI0MmN3cWcubFFvV0puUkZBM2tFVkFzQS5KR1M2TEpPNHNQSGRvVUo2ZnNxVzBKS"
         * +
         * "V9MWEhXTUd3OEk1RDFKeWx5S0M3b1FIREJGYlBWMTc0M1JlRXRoaUoybEp0LXdqWlNvNzV6RUN5dS1VS0llSXNFdmJGcVhPY2hYaWFZbi1KeDhzSVZxRWpRMWpCVk"
         * +
         * "V2RE0waW9Pbk02V29qVElPNGlmQkdCNUd4d2xHNVVIM2hLb0ZxeXNDTkZSYmpqMlMxSjJ3a1NvV3pSNVZhX2RMejRHM2tiY1VGd0ZHdVQ3T2tfZFBjZ1oxaFktVDR"
         * +
         * "TTURscnVqb1gxeUlLN2UyVXMyZFgxdjFaLWJ5VU5yMkJNTUZ2d1VTV1poRXdNZ2YwQ2RDRi1XOGlScF9wbl9QclA5WEc4dUM0U3U0b2QuWUliM0NMWVB1MFFqbFha"
         * +
         * "dVBPaUk5dw.qbE5FGkBqHrQWFGIMBa_jhW2QlW5NXAJFUSSMrW3vzd3icAI2J-MOMlvaEhhprVFN6w-Gaf9a3oLK7N_4gmrC3_lkOo7qwSuuy07-tqJEctKTTHMtS"
         * +
         * "zgQCuXcxj_0Wf2vNOQI_S1UO-yEZxadnQVwTDZyC5GSbZ_ki6gLyr41TM-vRJCBIzAAkw9nmhV3ys4Xf-F7HKnSO7_e9cDQltEjVZkJlRFDFoPf52PqryKA5FmMRI"
         * +
         * "yzmtl8BCSxAz972ASTCRFCfU6N8gR6KaxY8WOVs77vlcI73t06kdcmLmqUYZC1MPFTUCw5gwzr5nlLnZ91ESbLlDdVWy8VD0ioHta5w";
         */

        // ypylypen + OtpBankIssuerApiKey.SBX
        // String encryptedData =
        // "eyJ0eXAiOiJKT1NFIiwiYWxnIjoiUlMyNTYifQ.ZXlKMGVYQWlPaUpLVDFORklpd2laVzVqSWpvaVFURXlPRWREVFNJc0ltbGhkQ0k2TVRVek1EVTBNekkyTkN3aVlXeG5Jam9pVWxOQk1WODFJaXdpYTJsa0lqb2lSVTFPVVVjeVJqWlBXakJWVlRGWVFqSklOMGN4TTB0alpHWlVia1ZEWlZwV1NHNXZlbTVxTWtaRWMyMWhaMlIxVVNKOS5HclFTUnhzbTJzYnVLWEh5bFkyU2xRX082aXVrVU9jeDUyS2w1N1JZeW1CS2VjeWk4MG93S3c2dGJVa3ZYS0ZFUF9Mc05wZWdyaTdsLTlhaWZRdFNmR25BZHJOWDVobEhjYzRpRW1kRGUycWpQaDQ0NDFNemRsbzBvU1RJVUluLXFlclgzc2ZabVVHajYycWVYbnJ6cUJzU1pYS3JieUlRbktmYzR1eTRJYjBoX0h2bExZeE93dTd0WlZDY3Z3UF9ENHlvTG1mWEZHNmNmaGozN2VYMEFCUEQyS0IwTVRZUV9RZ1ZNZlNGTGNrQkpvemRzQTB2eXowOEE4R2E3SDZCRFNrOEJQQXcxTm9WVVN1Nkw1XzcwWW52dVBpOFRQVTI4eElSb0RaaEFWdmVfY1l5dGFKNG5USWZPT1oybUpUMGlFWlJSTDRUd3Fvak1DajZYMUpHWWcuc3dRT2FsV3drUFlhQmdGZS5OOHlPTjQ1QTgwTi1xSEpNb053Q2lZTnRGS1NFb1NrM1ZVYWVpTmxqWUxQQV9uSHkwS1JlRXpMa2lTOFRmOFpPY1EzVUN1Rll2NXM2RjZkLXJvbFdVZzlOYlZ6WlNiQWdXUmg2TmFqTk9Od1JseUdGUU1SWU14NXZSVllMN0VVVk9JX3ZTbk9nYmozN3FjcjNhYlJJT1dYdXBISXZFcHZFR3cwcnlhZ1ZQQ09VVFlyeEZ4UW4wdHZtNXNDMDNONXdEellfQ2NsSHROQVk4SVIwR3FpVXNPdlhsRkhLWmZsQmJJdUZnVl8wNnY0akx0VnpibkNmM2EySVZlRmRpWTI0Wk5NZkFURUFkTEgxQXlVWll5ODZuV001MC03MlVQTzdXaHJYUmt1MXlkb1hSMnBVMEJnNURQZ2JQTC05RWNNZ1lYZXFZZWtQcnFZdGxZajFWU2w1eTE4TlhfaW9Jd3d2Sm9vbDZhb1JKX1d6dzdnOW5LbnhBQWcuZ1M1aFloNjRWRV9wZ19RYUxlWnRKQQ.b0nm-zsQnokmlBomv-1gggfGKAhuNrVXqld1zN-Uudu8C2e07q8nm7qFiNJcsD_bFFHhMGX04_LJw8h24XE7GPe3iZaFZxuNpXo9AP7uzrlZdyKDWClhJqBx_numcMmr5E9MUVGOF9V2TQ3xSiOXJS6URzhxvqMsiPjQgaD4MvRrX_GpajrsVRAFKcTrfF3Zrs5SILHGzwLgKKlaEPeGQbYOIZs5Cef74HkaWrGNfsQwjR8uExfppA-EdrkemgZwhmLn9OM-cOeUymNVs9S3P5-FfLvisXdQJ--YwsM0x7YxhMLfUuC_kwEZqbot_1ER4tZKOhD5fczvua-Bc2i3FQ";

        // my
        String encryptedData = staticSignedEncryptedData;

        String clearedPem = pemEncodedCertificate.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "").replace(" ", "");

        byte[] asn1bytes = Base64.getDecoder().decode(clearedPem);

        KeyHandle cert = engine.rsaKeyAlg().createX509Certificate(asn1bytes);

        RsaKeyPublicData rsakpd = RsaKeyUtil.getRsaKeyPublicData(session, cert);
        RSAPublicKeySpec rsaPubKeySpec = new RSAPublicKeySpec(new BigInteger(1, rsakpd.getModulus()),
                new BigInteger(1, rsakpd.getPublicExponent()));
        RSAPublicKey rsaPubKey = (RSAPublicKey) KeyFactory.getInstance("RSA", Security.getProvider("SunRsaSign"))
                .generatePublic(rsaPubKeySpec);

        JWSObject jwsObject2Verify = JWSObject.parse(encryptedData);

        JWSVerifier verifier = new RSASSAVerifier(rsaPubKey);

        if (!jwsObject2Verify.verify(verifier))
            throw new JOSEException("JWS Signature verification failed");

        String pkiJwe = jwsObject2Verify.getPayload().toString();

        KeyHandle dk = SymmetricKeyUtil.generateKey(session, KEY_TYPE.DES3);
        KeyHandle privKey = engine.rsaKeyAlg().unwrapKey_LMK(HexUtil.hexToBytes(wrappedKey));
        byte[] privKeyUnderDk = RsaKeyUtil.wrapKey_DES3(session, privKey, dk);
        byte[] privKeyBytes = SymmetricKeyUtil.decrypt(session, dk, KEY_TYPE.DES3, privKeyUnderDk);
        RSAPrivateKeySpec rsaPrivKeySpec = RsaKeyUtil.buildPrivateKeySpec(privKeyBytes);

        PrivateKey rsaPrivKey = KeyFactory.getInstance("RSA", Security.getProvider("SunRsaSign"))
                .generatePrivate(rsaPrivKeySpec);

        JWEObject jweObject2Decrypt = JWEObject.parse(pkiJwe);

        RSADecrypter decrypter = new RSADecrypter(rsaPrivKey);

        jweObject2Decrypt.decrypt(decrypter);

        String result = jweObject2Decrypt.getPayload().toString();

        result = result.substring(result.indexOf('{'));

        System.out.println("Result = " + result);
    }

}
