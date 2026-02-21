package org.minima.objects.keys;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.minima.database.mmr.MMRData;
import org.minima.database.mmr.MMRProof;
import org.minima.objects.base.MiniData;
import org.minima.objects.base.MiniNumber;
import org.minima.utils.Streamable;
import org.minima.utils.json.JSONObject;

public class SignatureProof implements Streamable {

	/**
	 * Маркер версии нового формата.
	 * Старый формат начинается с длины MiniData, которая никогда не будет 0xFF.
	 */
	private static final byte VERSION_NEW_FORMAT = (byte) 0xFF;

	/**
	 * Тип схемы подписи (0=WOTS, 1=SPHINCS+)
	 */
	private int mSchemeType = SigningScheme.SCHEME_WINTERNITZ;

	private MiniData mPublicKey;

	private MiniData mSignature;

	private MMRProof mProof;

	private SignatureProof() {}

	/**
	 * Обратно-совместимый конструктор (Winternitz по умолчанию)
	 */
	public SignatureProof(MiniData zPublicKey, MiniData zSignature, MMRProof zProof) {
		this(zPublicKey, zSignature, zProof, SigningScheme.SCHEME_WINTERNITZ);
	}

	/**
	 * Конструктор с типом схемы
	 */
	public SignatureProof(MiniData zPublicKey, MiniData zSignature, MMRProof zProof, int zSchemeType) {
		mPublicKey 	= zPublicKey;
		mSignature 	= zSignature;
		mProof 		= zProof;
		mSchemeType = zSchemeType;
	}

	public MiniData getPublicKey() {
		return mPublicKey;
	}

	public MiniData getSignature() {
		return mSignature;
	}

	public MMRProof getProof() {
		return mProof;
	}

	public int getSchemeType() {
		return mSchemeType;
	}

	public MiniData getRootPublicKey(){
		// SPHINCS+ не использует дерево MMR — публичный ключ = root key напрямую
		if (mSchemeType == SigningScheme.SCHEME_SPHINCS) {
			return mPublicKey;
		}
		// Winternitz: вычисляем root через MMR proof
		MMRData pubentry = MMRData.CreateMMRDataLeafNode(mPublicKey, MiniNumber.ZERO);
		return mProof.calculateProof(pubentry).getData();
	}

	public JSONObject toJSON() {
		JSONObject json = new JSONObject();

		json.put("publickey", mPublicKey.to0xString());
		json.put("rootkey", getRootPublicKey().to0xString());
		json.put("proof", mProof.toJSON());
		json.put("signature", mSignature.to0xString());
		json.put("schemetype", mSchemeType);
		json.put("scheme", mSchemeType == SigningScheme.SCHEME_SPHINCS ? "SPHINCS+" : "WINTERNITZ");

		return json;
	}

	@Override
	public void writeDataStream(DataOutputStream zOut) throws IOException {
		// Записываем маркер нового формата
		zOut.writeByte(VERSION_NEW_FORMAT);

		// Записываем тип схемы
		zOut.writeByte(mSchemeType);

		// Остальное — как раньше
		mPublicKey.writeDataStream(zOut);
		mSignature.writeDataStream(zOut);
		mProof.writeDataStream(zOut);
	}

	@Override
	public void readDataStream(DataInputStream zIn) throws IOException {
		// Читаем первый байт
		zIn.mark(1);
		byte firstByte = zIn.readByte();

		if (firstByte == VERSION_NEW_FORMAT) {
			// Новый формат — читаем тип схемы
			mSchemeType = zIn.readByte();
		} else {
			// Старый формат — откатываем назад
			zIn.reset();
			mSchemeType = SigningScheme.SCHEME_WINTERNITZ;
		}

		// Остальное — как раньше
		mPublicKey	= MiniData.ReadFromStream(zIn);
		mSignature 	= MiniData.ReadFromStream(zIn);
		mProof		= MMRProof.ReadFromStream(zIn);
	}

	public static SignatureProof ReadFromStream(DataInputStream zIn) throws IOException {
		SignatureProof sig = new SignatureProof();
		sig.readDataStream(zIn);
		return sig;
	}
}
