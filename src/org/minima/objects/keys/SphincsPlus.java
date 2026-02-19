package org.minima.objects.keys;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusSigner;

import org.minima.objects.base.MiniData;
import org.minima.utils.Crypto;

/**
 * Низкоуровневая обёртка над BouncyCastle SPHINCS+.
 * Аналог класса Winternitz — предоставляет sign/verify/getPublicKey.
 *
 * Использует SHAKE-128s (SHA-3/SHAKE-256, компактные подписи ~7 КБ, ключ 32 байта).
 * Это stateless схема — не нужен счётчик использований.
 */
public class SphincsPlus {

	/**
	 * Параметры SPHINCS+
	 * shake_128s — на основе SHAKE-256 (SHA-3), 128-бит безопасности, подпись ~7 КБ
	 *
	 * Альтернативы:
	 *   shake_256s — максимальная безопасность (256 бит), подпись ~30 КБ
	 *   sha2_128s — на основе SHA-256, ~7 КБ
	 *   sha2_256s — SHA-256, 256 бит, ~30 КБ
	 */
	public static final SPHINCSPlusParameters SPHINCS_PARAMS = SPHINCSPlusParameters.shake_128s;

	private SPHINCSPlusPrivateKeyParameters mPrivateKey;
	private SPHINCSPlusPublicKeyParameters  mPublicKey;
	private MiniData mPublicKeyData;
	private MiniData mPrivateSeed;

	/**
	 * Пустой конструктор (для статической верификации)
	 */
	public SphincsPlus() {}

	/**
	 * Создать ключевую пару из seed.
	 * Seed хешируется для получения детерминированной энтропии.
	 */
	public SphincsPlus(MiniData zPrivateSeed) {
		mPrivateSeed = zPrivateSeed;

		// Детерминированная генерация ключей из seed
		// Создаём SecureRandom с фиксированным seed для детерминизма
		byte[] seedBytes = zPrivateSeed.getBytes();
		SecureRandom deterministicRandom = new FixedSecureRandom(seedBytes);

		SPHINCSPlusKeyPairGenerator keyGen = new SPHINCSPlusKeyPairGenerator();
		keyGen.init(new SPHINCSPlusKeyGenerationParameters(deterministicRandom, SPHINCS_PARAMS));

		AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();
		mPrivateKey = (SPHINCSPlusPrivateKeyParameters) keyPair.getPrivate();
		mPublicKey  = (SPHINCSPlusPublicKeyParameters)  keyPair.getPublic();

		mPublicKeyData = new MiniData(mPublicKey.getEncoded());
	}

	public MiniData getPublicKey() {
		return mPublicKeyData;
	}

	public MiniData getPrivateSeed() {
		return mPrivateSeed;
	}

	/**
	 * Подписать данные
	 */
	public MiniData sign(MiniData zData) {
		SPHINCSPlusSigner signer = new SPHINCSPlusSigner();
		signer.init(true, mPrivateKey);
		byte[] sig = signer.generateSignature(zData.getBytes());
		return new MiniData(sig);
	}

	/**
	 * Верифицировать подпись (статический метод — как у Winternitz)
	 */
	public static boolean verify(MiniData zPublicKey, MiniData zData, MiniData zSignature) {
		try {
			SPHINCSPlusPublicKeyParameters pubKey =
				new SPHINCSPlusPublicKeyParameters(SPHINCS_PARAMS, zPublicKey.getBytes());
			SPHINCSPlusSigner signer = new SPHINCSPlusSigner();
			signer.init(false, pubKey);
			return signer.verifySignature(zData.getBytes(), zSignature.getBytes());
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * Детерминированный SecureRandom на основе seed.
	 * Используется ТОЛЬКО для генерации ключей из мнемонической фразы.
	 *
	 * Расширяет seed через SHA3-256 цепочку хешей для получения
	 * достаточного количества псевдослучайных байтов.
	 */
	static class FixedSecureRandom extends SecureRandom {

		private static final long serialVersionUID = 1L;

		private byte[] mSeed;
		private int mPosition;
		private byte[] mBuffer;

		public FixedSecureRandom(byte[] zSeed) {
			// Расширяем seed через цепочку хешей
			// Это даёт нам детерминированный поток байтов произвольной длины
			mSeed = zSeed;
			mPosition = 0;

			// Предварительно генерируем достаточно байтов
			// SPHINCS+ sha2_128s требует ~96 байтов seed
			// Генерируем с запасом (1024 байта)
			mBuffer = expandSeed(zSeed, 1024);
		}

		private byte[] expandSeed(byte[] seed, int length) {
			byte[] result = new byte[length];
			int offset = 0;
			int counter = 0;

			while (offset < length) {
				// hash(seed || counter) для каждого блока
				byte[] counterBytes = new byte[4];
				counterBytes[0] = (byte) ((counter >> 24) & 0xFF);
				counterBytes[1] = (byte) ((counter >> 16) & 0xFF);
				counterBytes[2] = (byte) ((counter >> 8) & 0xFF);
				counterBytes[3] = (byte) (counter & 0xFF);

				// Конкатенация seed + counter
				byte[] input = new byte[seed.length + 4];
				System.arraycopy(seed, 0, input, 0, seed.length);
				System.arraycopy(counterBytes, 0, input, seed.length, 4);

				// SHA3-256 хеш
				byte[] hash = Crypto.getInstance().hashData(input);

				// Копируем в результат
				int toCopy = Math.min(hash.length, length - offset);
				System.arraycopy(hash, 0, result, offset, toCopy);
				offset += toCopy;
				counter++;
			}

			return result;
		}

		@Override
		public void nextBytes(byte[] bytes) {
			if (mPosition + bytes.length > mBuffer.length) {
				// Расширяем буфер если не хватает
				mBuffer = expandSeed(mSeed, mPosition + bytes.length + 1024);
			}
			System.arraycopy(mBuffer, mPosition, bytes, 0, bytes.length);
			mPosition += bytes.length;
		}

		@Override
		public byte[] generateSeed(int numBytes) {
			byte[] result = new byte[numBytes];
			nextBytes(result);
			return result;
		}
	}
}
