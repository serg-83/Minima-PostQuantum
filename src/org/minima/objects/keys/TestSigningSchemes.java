WARNING: linker: Warning: failed to find generated linker configuration from "/linkerconfig/ld.config.txt"
package org.minima.objects.keys;

import org.minima.objects.base.MiniData;
import org.minima.utils.MinimaLogger;

/**
 * Тест взаимозаменяемости Winternitz и SPHINCS+.
 *
 * Запуск:
 *   java -cp build:lib/* org.minima.objects.keys.TestSigningSchemes
 */
public class TestSigningSchemes {

	public static void main(String[] args) {

		MinimaLogger.log("========================================");
		MinimaLogger.log("  Тест SigningScheme: WOTS vs SPHINCS+");
		MinimaLogger.log("========================================");
		MinimaLogger.log("");

		// Общий seed
		MiniData seed = MiniData.getRandomData(32);
		MiniData data = MiniData.getRandomData(32);

		MinimaLogger.log("Seed: " + seed.to0xString(32));
		MinimaLogger.log("Data: " + data.to0xString(32));
		MinimaLogger.log("");

		// ===== ТЕСТ 1: Winternitz через SigningScheme =====
		MinimaLogger.log("--- ТЕСТ 1: WinternitzScheme ---");
		long t1 = System.currentTimeMillis();

		SigningScheme wots = SigningSchemeFactory.createScheme(
			SigningScheme.SCHEME_WINTERNITZ, seed);

		long t2 = System.currentTimeMillis();
		MinimaLogger.log("  Тип: " + wots.getSchemeType() + " (WINTERNITZ)");
		MinimaLogger.log("  PublicKey: " + wots.getPublicKey().to0xString(32));
		MinimaLogger.log("  MaxUses: " + wots.getMaxUses());
		MinimaLogger.log("  Size: " + wots.getSize() + ", Depth: " + wots.getDepth());
		MinimaLogger.log("  Генерация ключа: " + (t2 - t1) + " мс");

		// Подписываем
		t1 = System.currentTimeMillis();
		Signature wotsSig = wots.sign(data);
		t2 = System.currentTimeMillis();
		MinimaLogger.log("  Подпись: " + (t2 - t1) + " мс");
		MinimaLogger.log("  Uses после подписи: " + wots.getUses());

		// Верифицируем
		t1 = System.currentTimeMillis();
		boolean wotsValid = wots.verify(data, wotsSig);
		t2 = System.currentTimeMillis();
		MinimaLogger.log("  Верификация: " + wotsValid + " (" + (t2 - t1) + " мс)");
		MinimaLogger.log("");

		// ===== ТЕСТ 2: SPHINCS+ через SigningScheme =====
		MinimaLogger.log("--- ТЕСТ 2: SphincsScheme ---");
		t1 = System.currentTimeMillis();

		SigningScheme sphincs = SigningSchemeFactory.createScheme(
			SigningScheme.SCHEME_SPHINCS, seed);

		t2 = System.currentTimeMillis();
		MinimaLogger.log("  Тип: " + sphincs.getSchemeType() + " (SPHINCS+)");
		MinimaLogger.log("  PublicKey: " + sphincs.getPublicKey().to0xString(32));
		MinimaLogger.log("  MaxUses: " + sphincs.getMaxUses() + " (безлимитно)");
		MinimaLogger.log("  Size: " + sphincs.getSize() + ", Depth: " + sphincs.getDepth());
		MinimaLogger.log("  Генерация ключа: " + (t2 - t1) + " мс");

		// Подписываем
		t1 = System.currentTimeMillis();
		Signature sphincsSig = sphincs.sign(data);
		t2 = System.currentTimeMillis();
		MinimaLogger.log("  Подпись: " + (t2 - t1) + " мс");
		MinimaLogger.log("  Uses после подписи: " + sphincs.getUses());

		// Верифицируем
		t1 = System.currentTimeMillis();
		boolean sphincsValid = sphincs.verify(data, sphincsSig);
		t2 = System.currentTimeMillis();
		MinimaLogger.log("  Верификация: " + sphincsValid + " (" + (t2 - t1) + " мс)");
		MinimaLogger.log("");

		// ===== ТЕСТ 3: Множественные подписи SPHINCS+ (stateless) =====
		MinimaLogger.log("--- ТЕСТ 3: Множественные подписи SPHINCS+ ---");
		for (int i = 0; i < 3; i++) {
			MiniData testData = MiniData.getRandomData(32);
			Signature sig = sphincs.sign(testData);
			boolean valid = sphincs.verify(testData, sig);
			MinimaLogger.log("  Подпись #" + (i + 1) + ": valid=" + valid + ", uses=" + sphincs.getUses());
		}
		MinimaLogger.log("");

		// ===== ТЕСТ 4: Перекрёстная проверка (должна ПРОВАЛИТЬСЯ) =====
		MinimaLogger.log("--- ТЕСТ 4: Перекрёстная проверка ---");
		boolean crossValid1 = wots.verify(data, sphincsSig);
		MinimaLogger.log("  WOTS.verify(sphincs_sig): " + crossValid1 + " (ожидалось: false)");

		boolean crossValid2 = sphincs.verify(data, wotsSig);
		MinimaLogger.log("  SPHINCS.verify(wots_sig): " + crossValid2 + " (ожидалось: false)");
		MinimaLogger.log("");

		// ===== ТЕСТ 5: Фабричная верификация =====
		MinimaLogger.log("--- ТЕСТ 5: SigningSchemeFactory.verify() ---");
		SignatureProof wotsProof = wotsSig.getAllSignatureProofs().get(
			wotsSig.getAllSignatureProofs().size() - 1);
		boolean factoryWots = SigningSchemeFactory.verify(
			SigningScheme.SCHEME_WINTERNITZ,
			wotsProof.getPublicKey(), data, wotsProof.getSignature());
		MinimaLogger.log("  Factory WOTS verify: " + factoryWots);

		SignatureProof sphincsProof = sphincsSig.getAllSignatureProofs().get(0);
		boolean factorySphincs = SigningSchemeFactory.verify(
			SigningScheme.SCHEME_SPHINCS,
			sphincsProof.getPublicKey(), data, sphincsProof.getSignature());
		MinimaLogger.log("  Factory SPHINCS verify: " + factorySphincs);
		MinimaLogger.log("");

		// ===== ИТОГ =====
		MinimaLogger.log("========================================");
		boolean allPassed = wotsValid && sphincsValid && !crossValid1 && !crossValid2
			&& factoryWots && factorySphincs;
		if (allPassed) {
			MinimaLogger.log("  ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!");
		} else {
			MinimaLogger.log("  ЕСТЬ ПРОВАЛЫ!");
		}
		MinimaLogger.log("========================================");
	}
}
