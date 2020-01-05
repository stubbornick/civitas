/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */
package civitas.crypto.concrete;

import java.math.BigInteger;
import java.security.Security;
import java.security.SecureRandom;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.spec.ECGenParameterSpec;

import civitas.crypto.common.Base64;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.ECDecryptor;
import org.bouncycastle.crypto.ec.ECElGamalDecryptor;
import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TestElGamalBC {
	public String pointToString(ECPoint point) {
		return Base64.encodeBytes(point.getEncoded(true));
	}

	public String pairToString(ECPair pair) {
		StringBuffer sb = new StringBuffer();
		sb.append('{');
		sb.append(pointToString(pair.getX()));
		sb.append(',');
		sb.append(pointToString(pair.getY()));
		sb.append('}');
		return sb.toString();
	}

	public void testSimpleEncryption() throws Exception {
		BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

		ECCurve.Fp curve = new ECCurve.Fp(new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
				new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
				new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
				n, ECConstants.ONE);

		ECDomainParameters params = new ECDomainParameters(curve,
				curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
				n);

		ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
				curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), // Q
				params);

		ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
				new BigInteger("651056770906015076056810763456358567190100156695615665659"), // d
				params);

		ParametersWithRandom pRandom = new ParametersWithRandom(pubKey, new SecureRandom());

		BigInteger value = BigInteger.valueOf(20);

		ECPoint data = priKey.getParameters().getG().multiply(value);
		System.out.println("Data point: " + pointToString(data));

		ECEncryptor encryptor = new ECElGamalEncryptor();
		encryptor.init(pRandom);
		ECPair pair = encryptor.encrypt(data);
		System.out.println("Encrypted pair: " + pairToString(pair));

		ECDecryptor decryptor = new ECElGamalDecryptor();
		decryptor.init(priKey);
		ECPoint result = decryptor.decrypt(pair);
		System.out.println("Decrypted point: " + pointToString(result));
		System.out.println("Result of comparison: " + result.equals(data));

		if (!data.equals(result)) {
			throw new Exception("point pair failed to decrypt back to original");
		}

		System.out.println("OK");
	}

	public ECPair pairSum(ECPair pair1, ECPair pair2) {
		return new ECPair(pair1.getX().add(pair2.getX()), pair1.getY().add(pair2.getY()));
	}

	public void testHomomorphism() throws Exception {
		BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

		ECCurve.Fp curve = new ECCurve.Fp(new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
				new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
				new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
				n, ECConstants.ONE);

		ECDomainParameters params = new ECDomainParameters(curve,
				curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
				n);

		ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
				curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), // Q
				params);

		ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
				new BigInteger("651056770906015076056810763456358567190100156695615665659"), // d
				params);

		ParametersWithRandom pRandom = new ParametersWithRandom(pubKey, new SecureRandom());

		BigInteger value1 = BigInteger.valueOf(20);
		BigInteger value2 = BigInteger.valueOf(55);

		ECPoint data1 = priKey.getParameters().getG().multiply(value1);
		ECPoint data2 = priKey.getParameters().getG().multiply(value2);
		ECPoint dataSum = data1.add(data2);
		System.out.println("Data1 point: " + pointToString(data1));
		System.out.println("Data2 point: " + pointToString(data2));
		System.out.println("Data Sum point: " + pointToString(dataSum));

		ECEncryptor encryptor = new ECElGamalEncryptor();
		encryptor.init(pRandom);
		ECPair pair1 = encryptor.encrypt(data1);
		ECPair pair2 = encryptor.encrypt(data2);
		ECPair pairSum = pairSum(pair1, pair2);
		System.out.println("Encrypted pair1: " + pairToString(pair1));
		System.out.println("Encrypted pair2: " + pairToString(pair2));
		System.out.println("Sum of encrypted: " + pairToString(pairSum));

		ECDecryptor decryptor = new ECElGamalDecryptor();
		decryptor.init(priKey);
		ECPoint result1 = decryptor.decrypt(pair1);
		ECPoint result2 = decryptor.decrypt(pair2);
		ECPoint resultSum = decryptor.decrypt(pairSum);
		System.out.println("Decrypted point1: " + pointToString(result1));
		System.out.println("Decrypted point2: " + pointToString(result2));
		System.out.println("Decrypted sum: " + pointToString(resultSum));
		System.out.println("Result of comparison: " + resultSum.equals(dataSum));

		if (!dataSum.equals(resultSum)) {
			throw new Exception("point pair failed to decrypt back to original");
		}

		System.out.println("OK");
	}

	public void testSECCurveKeygenProvider() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", "BC");
		kpgen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
		KeyPair keypair = kpgen.generateKeyPair();
		System.out.println("Private key: " + Base64.encodeBytes(keypair.getPrivate().getEncoded()));
		System.out.println("Public key: " + Base64.encodeBytes(keypair.getPublic().getEncoded()));
	}

	public void testSECCurveKeygenRaw() throws Exception
	{
		ECParameterSpec secp256k1 = ECNamedCurveTable.getParameterSpec("secp256k1");

		ECDomainParameters params = new ECDomainParameters(
			secp256k1.getCurve(),
			secp256k1.getG(),
			secp256k1.getN()
			);

		ECKeyGenerationParameters keyParams = new ECKeyGenerationParameters(params, new SecureRandom());
		ECKeyPairGenerator generator = new ECKeyPairGenerator();
		generator.init(keyParams);
		AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
		ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)keyPair.getPrivate();
		ECPublicKeyParameters publicKey = (ECPublicKeyParameters)keyPair.getPublic();
		System.out.println("Private key: " + Base64.encodeBytes(privateKey.getD().toByteArray()));
		System.out.println("Public key: " + Base64.encodeBytes(publicKey.getQ().getEncoded(true)));
	}

	public void testSECCurveEncryption() throws Exception
	{
		ECParameterSpec secp256k1 = ECNamedCurveTable.getParameterSpec("secp256k1");

		ECDomainParameters params = new ECDomainParameters(
			secp256k1.getCurve(),
			secp256k1.getG(),
			secp256k1.getN()
			);

		byte[] PRIVATE_KEY = Base64.decode("boZgsbMc9xWs1t6HSBInS4QZUh0TakIfdBWiaubTIhg=");
		byte[] PUBLIC_KEY = Base64.decode("Av858ZH43EW0L4XVbAstLjMzFx1YE5hY3/dqpuRxO4+Q");

		BigInteger privateD = new BigInteger(PRIVATE_KEY);
		ECPoint publicQ = params.getCurve().decodePoint(PUBLIC_KEY);

		ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(privateD, params);
		ECPublicKeyParameters publicKey = new ECPublicKeyParameters(publicQ, params);

		System.out.println("Private key: " + Base64.encodeBytes(privateKey.getD().toByteArray()));
		System.out.println("Public key: " + Base64.encodeBytes(publicKey.getQ().getEncoded(true)));

		ParametersWithRandom pRandom = new ParametersWithRandom(publicKey, new SecureRandom());

		BigInteger value = BigInteger.valueOf(20);

		ECPoint data = privateKey.getParameters().getG().multiply(value);
		System.out.println("Data point: " + pointToString(data));

		ECEncryptor encryptor = new ECElGamalEncryptor();
		encryptor.init(pRandom);
		ECPair pair = encryptor.encrypt(data);
		System.out.println("Encrypted pair: " + pairToString(pair));

		ECDecryptor decryptor = new ECElGamalDecryptor();
		decryptor.init(privateKey);
		ECPoint result = decryptor.decrypt(pair);
		System.out.println("Decrypted point: " + pointToString(result));
		System.out.println("Result of comparison: " + result.equals(data));

		if (!data.equals(result)) {
			throw new Exception("point pair failed to decrypt back to original");
		}

		System.out.println("OK");
	}

    public static void main (String [] args) throws Exception
	{
		TestElGamalBC test = new TestElGamalBC();

		System.out.println("== Test encryption ==");
		test.testSimpleEncryption();
		System.out.println("== Test homomorphism property ==");
		test.testHomomorphism();

		System.out.println("== Test SEC curve key generation (provider) ==");
		test.testSECCurveKeygenProvider();
		System.out.println("== Test SEC curve key generation (raw curve) ==");
		test.testSECCurveKeygenRaw();
		System.out.println("== Test SEC curve encryption ==");
		test.testSECCurveEncryption();
	}
}