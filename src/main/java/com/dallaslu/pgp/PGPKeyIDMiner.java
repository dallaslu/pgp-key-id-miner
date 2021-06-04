package com.dallaslu.pgp;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

public class PGPKeyIDMiner {
	private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
	private static final AtomicInteger counter = new AtomicInteger();

	private static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = HEX_ARRAY[v >>> 4];
			hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
		}
		return new String(hexChars);
	}

	private static boolean endsWith(byte[] bytes, String end) {
		char[] endChar = end.toCharArray();
		for (int i = 0; i < endChar.length; i += 2) {
			int v = bytes[bytes.length - 1 - (endChar.length - 1 - i) / 2] & 0xFF;
			char c1 = HEX_ARRAY[v >>> 4];
			char c2 = HEX_ARRAY[v & 0x0F];
			if ((endChar[i] == '_' || c1 == endChar[i]) && (endChar[i + 1] == '_' || c2 == endChar[i + 1])) {
				continue;
			} else {
				return false;
			}
		}
		return true;
	}

	private static String genPassphrase() {
		int leftLimit = 48; // numeral '0'
		int rightLimit = 122; // letter 'z'
		int targetStringLength = 20;
		Random random = new Random();

		String generatedString = random.ints(leftLimit, rightLimit + 1)
				.filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97)).limit(targetStringLength)
				.collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString();
		return generatedString;
	}

	public static void main(String[] args) throws ParseException {
		final String datePattern = "\\d+-\\d\\d-[0-3]\\d+";
		String timeStartString = null;// "2021-02-01 00:00:00";
		String timeEndString = null;// "2021-02-01 00:00:00";
		List<String> patternsList = new ArrayList<>();
		if (args != null) {
			int index = 0;
			while (index < args.length) {
				String a = args[index];
				if (index == 0) {
					if (a.matches(datePattern)) {
						timeStartString = a;
					}
				}
				if (index == 1) {
					if (timeStartString != null && a.matches(datePattern)) {
						timeEndString = a;
					}
				}
				if (a.length() % 2 == 1) {
					a = '_' + a;
				}
				patternsList.add(a);
				index++;
			}
		}

		if (patternsList.size() == 0) {
			patternsList.add("000000");
			patternsList.add("000_____000_____");
		}

		final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		final String name = "Fake Name";
		final String email = "fake@example.org";
		final String pass = genPassphrase();
		final Date start = sdf.parse(timeStartString == null ? "2021-02-01 00:00:00" : timeStartString);
		final Date end = timeEndString == null ? new Date() : sdf.parse(timeStartString);
		final String[] patterns = patternsList.toArray(new String[0]);

		int threadNum = Runtime.getRuntime().availableProcessors();
		ExecutorService es = Executors.newFixedThreadPool(threadNum);

		for (int i = 0; i < threadNum; i++) {
			es.execute(() -> {
				try {
					new PGPKeyIDMiner().gen(name, email, pass, patterns, start, end, ".");
				} catch (NoSuchAlgorithmException | PGPException | IOException e) {
					e.printStackTrace();
				}
			});
		}

		while (true) {
			try {
				System.out.println(String.format("%s #%s", new Date(), counter.get()));
				Thread.sleep(10 * 1000L);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

	private static boolean match(byte[] bytes, String[] patterns) {
		for (String e : patterns) {
			if (endsWith(bytes, e)) {
				return true;
			}
		}
		return false;
	}

	public void gen(String name, String email, String pass, String[] patterns, Date start, Date end, String folder)
			throws NoSuchAlgorithmException, PGPException, IOException {
		char[] passwd = pass.toCharArray();
		String uid = name == null ? email : String.format("%s <%s>", name, email);
		Security.addProvider(new BouncyCastleProvider());
		PGPKeyPair pkpSign = null;
		String fp = null;
		{
			KeyPair kpSign = null;
			long time = 0;
			long now = System.currentTimeMillis();
			do {

				if (pkpSign == null || time <= start.getTime()) {
					time = end.getTime();
					KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
					kpg.initialize(256, new SecureRandom());
					kpSign = kpg.generateKeyPair();
				}
				time -= 1000;
				pkpSign = new JcaPGPKeyPair(PGPPublicKey.EDDSA, kpSign, new Date(time));
				counter.incrementAndGet();
			} while (!match(pkpSign.getPublicKey().getFingerprint(), patterns));
			fp = bytesToHex(pkpSign.getPublicKey().getFingerprint());
			System.out.println(String.format("%s Got %s (%s), used %ss. #%s", new Date(), fp, new Date(time + 1000),
					(System.currentTimeMillis() - now) / 1000, counter.get()));
		}

		PGPSignatureSubpacketGenerator pssg = new PGPSignatureSubpacketGenerator();
		pssg.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
		pssg.setPreferredSymmetricAlgorithms(false,
				new int[] { SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192,
						SymmetricKeyAlgorithmTags.AES_128, SymmetricKeyAlgorithmTags.CAST5 });
		pssg.setPreferredHashAlgorithms(false, new int[] { HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384,
				HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA224, HashAlgorithmTags.SHA1, });
		pssg.setPreferredCompressionAlgorithms(false, new int[] { CompressionAlgorithmTags.ZLIB,
				CompressionAlgorithmTags.BZIP2, CompressionAlgorithmTags.ZIP, CompressionAlgorithmTags.UNCOMPRESSED });
		pssg.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

		PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
		PGPDigestCalculator sha256Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);

		PBESecretKeyEncryptor pske = (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc, 0xc0))
				.build(passwd);

		PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, pkpSign, uid,
				sha1Calc, pssg.generate(), null,
				new BcPGPContentSignerBuilder(pkpSign.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), pske);
		PGPPublicKeyRing pkr = keyRingGen.generatePublicKeyRing();
		ArmoredOutputStream pubout = new ArmoredOutputStream(
				new BufferedOutputStream(new FileOutputStream(folder + File.separator + fp + ".pub")));
		pkr.encode(pubout);
		pubout.close();

		// dump to file.
		PGPSecretKeyRing skr = keyRingGen.generateSecretKeyRing();
		BufferedOutputStream secout = new BufferedOutputStream(
				new FileOutputStream(folder + File.separator + fp + ".sec"));
		skr.encode(secout);
		secout.close();
		System.out.println(String.format("%s Dumped with passphrase: %s", new Date(), pass));
	}
}
