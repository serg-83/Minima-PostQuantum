package org.minima.objects.keys;

import org.minima.objects.base.MiniData;

/**
 * Фабрика для создания SigningScheme.
 * Централизованная точка выбора схемы подписи.
 *
 * Используется в Wallet для создания ключей и подписания.
 */
public class SigningSchemeFactory {

	/**
	 * Создать новую схему подписи с параметрами по умолчанию.
	 *
	 * @param zSchemeType — тип схемы: SigningScheme.SCHEME_WINTERNITZ или SCHEME_SPHINCS
	 * @param zPrivateSeed — приватный seed для генерации ключей
	 */
	public static SigningScheme createScheme(int zSchemeType, MiniData zPrivateSeed) {
		switch (zSchemeType) {
			case SigningScheme.SCHEME_SPHINCS:
				return new SphincsScheme(zPrivateSeed);

			case SigningScheme.SCHEME_WINTERNITZ:
			default:
				return new WinternitzScheme(zPrivateSeed);
		}
	}

	/**
	 * Восстановить схему подписи из БД (с заданными параметрами дерева).
	 *
	 * @param zSchemeType — тип схемы
	 * @param zPrivateSeed — приватный seed
	 * @param zSize — ширина дерева (keysPerLevel). Игнорируется для SPHINCS+.
	 * @param zDepth — глубина дерева (levels). Игнорируется для SPHINCS+.
	 */
	public static SigningScheme restoreScheme(int zSchemeType, MiniData zPrivateSeed, int zSize, int zDepth) {
		switch (zSchemeType) {
			case SigningScheme.SCHEME_SPHINCS:
				return new SphincsScheme(zPrivateSeed);

			case SigningScheme.SCHEME_WINTERNITZ:
			default:
				return new WinternitzScheme(zPrivateSeed, zSize, zDepth);
		}
	}

	/**
	 * Верифицировать подпись, зная тип схемы.
	 *
	 * Используется для верификации подписей из сети,
	 * когда тип схемы определяется из SignatureProof.
	 */
	public static boolean verify(int zSchemeType, MiniData zPublicKey, MiniData zData, MiniData zSignature) {
		switch (zSchemeType) {
			case SigningScheme.SCHEME_SPHINCS:
				return SphincsPlus.verify(zPublicKey, zData, zSignature);

			case SigningScheme.SCHEME_WINTERNITZ:
			default:
				return Winternitz.verify(zPublicKey, zData, zSignature);
		}
	}
}
