WARNING: linker: Warning: failed to find generated linker configuration from "/linkerconfig/ld.config.txt"
package org.minima.objects.keys;

import org.minima.database.mmr.MMRProof;
import org.minima.objects.base.MiniData;

/**
 * Реализация SigningScheme для SPHINCS+.
 *
 * SPHINCS+ — stateless многоразовая схема подписи.
 * В отличие от Winternitz, НЕ требует дерева ключей (TreeKey).
 * Один ключ может подписывать неограниченное число сообщений.
 *
 * Подпись содержит ровно один SignatureProof (без цепочки уровней дерева).
 * При верификации проверяется только этот один proof.
 */
public class SphincsScheme implements SigningScheme {

	private SphincsPlus mKey;
	private MiniData mPrivateSeed;
	private int mUses = 0;

	/**
	 * Создать новый ключ из seed (для генерации нового адреса)
	 */
	public SphincsScheme(MiniData zPrivateSeed) {
		mPrivateSeed = zPrivateSeed;
		mKey = new SphincsPlus(zPrivateSeed);
	}

	@Override
	public int getSchemeType() {
		return SigningScheme.SCHEME_SPHINCS;
	}

	@Override
	public MiniData getPublicKey() {
		return mKey.getPublicKey();
	}

	@Override
	public MiniData getPrivateKey() {
		return mPrivateSeed;
	}

	@Override
	public Signature sign(MiniData zData) {

		// Подписываем данные
		MiniData sigData = mKey.sign(zData);
		MiniData pubKey  = mKey.getPublicKey();

		// SPHINCS+ не использует дерево MMR — создаём пустой proof.
		// При верификации getRootPublicKey() на пустом proof
		// просто вернёт хеш самого публичного ключа.
		// Это корректно, т.к. SPHINCS+ подпись содержит только один уровень.
		MMRProof emptyProof = new MMRProof();

		SignatureProof sigProof = new SignatureProof(pubKey, sigData, emptyProof);

		Signature signature = new Signature();
		signature.addSignatureProof(sigProof);

		// Считаем использования для статистики (не для безопасности)
		mUses++;

		return signature;
	}

	@Override
	public boolean verify(MiniData zData, Signature zSignature) {
		// SPHINCS+ подпись содержит ровно один SignatureProof
		if (zSignature.getAllSignatureProofs().size() != 1) {
			return false;
		}

		SignatureProof proof = zSignature.getAllSignatureProofs().get(0);
		return SphincsPlus.verify(proof.getPublicKey(), zData, proof.getSignature());
	}

	@Override
	public int getUses() {
		return mUses;
	}

	@Override
	public int getMaxUses() {
		return -1; // Безлимитно
	}

	@Override
	public void setUses(int zUses) {
		mUses = zUses;
	}

	@Override
	public int getSize() {
		return 1; // Нет дерева — один ключ
	}

	@Override
	public int getDepth() {
		return 1; // Один уровень
	}
}
