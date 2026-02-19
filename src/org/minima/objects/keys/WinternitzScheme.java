package org.minima.objects.keys;

import org.minima.objects.base.MiniData;

/**
 * Реализация SigningScheme для Winternitz (WOTS) через TreeKey.
 * Это обёртка — вся логика остаётся в TreeKey/TreeKeyNode/Winternitz.
 * Полностью обратно совместима с существующим кодом.
 */
public class WinternitzScheme implements SigningScheme {

	private TreeKey mTreeKey;

	/**
	 * Создать с параметрами по умолчанию (64 ключа, 3 уровня = 262144 подписи)
	 */
	public WinternitzScheme(MiniData zPrivateSeed) {
		mTreeKey = TreeKey.createDefault(zPrivateSeed);
	}

	/**
	 * Создать с заданными параметрами (для восстановления из БД)
	 */
	public WinternitzScheme(MiniData zPrivateSeed, int zKeysPerLevel, int zLevels) {
		mTreeKey = new TreeKey(zPrivateSeed, zKeysPerLevel, zLevels);
	}

	@Override
	public int getSchemeType() {
		return SigningScheme.SCHEME_WINTERNITZ;
	}

	@Override
	public MiniData getPublicKey() {
		return mTreeKey.getPublicKey();
	}

	@Override
	public MiniData getPrivateKey() {
		return mTreeKey.getPrivateKey();
	}

	@Override
	public Signature sign(MiniData zData) {
		return mTreeKey.sign(zData);
	}

	@Override
	public boolean verify(MiniData zData, Signature zSignature) {
		return mTreeKey.verify(zData, zSignature);
	}

	@Override
	public int getUses() {
		return mTreeKey.getUses();
	}

	@Override
	public int getMaxUses() {
		return mTreeKey.getMaxUses();
	}

	@Override
	public void setUses(int zUses) {
		mTreeKey.setUses(zUses);
	}

	@Override
	public int getSize() {
		return mTreeKey.getSize();
	}

	@Override
	public int getDepth() {
		return mTreeKey.getDepth();
	}
}
