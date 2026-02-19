package org.minima.objects.keys;

import org.minima.objects.base.MiniData;

/**
 * Абстрактный интерфейс схемы подписи.
 * Позволяет взаимозаменяемо использовать Winternitz (WOTS) и SPHINCS+.
 *
 * Winternitz — одноразовая подпись (stateful, требует дерево TreeKey).
 * SPHINCS+ — многоразовая подпись (stateless, дерево не нужно).
 */
public interface SigningScheme {

	/**
	 * Типы схем подписи
	 */
	public static final int SCHEME_WINTERNITZ 	= 0;
	public static final int SCHEME_SPHINCS 		= 1;

	/**
	 * Возвращает тип схемы (SCHEME_WINTERNITZ или SCHEME_SPHINCS)
	 */
	int getSchemeType();

	/**
	 * Публичный ключ
	 */
	MiniData getPublicKey();

	/**
	 * Приватный seed
	 */
	MiniData getPrivateKey();

	/**
	 * Подписать данные
	 */
	Signature sign(MiniData zData);

	/**
	 * Верифицировать подпись
	 */
	boolean verify(MiniData zData, Signature zSignature);

	/**
	 * Текущее число использований
	 */
	int getUses();

	/**
	 * Максимум использований (-1 = безлимитно)
	 */
	int getMaxUses();

	/**
	 * Установить число использований (для восстановления из БД)
	 */
	void setUses(int zUses);

	/**
	 * Ширина дерева (keysPerLevel). Для SPHINCS+ возвращает 1.
	 */
	int getSize();

	/**
	 * Глубина дерева. Для SPHINCS+ возвращает 1.
	 */
	int getDepth();
}
