package org.minima.database.wallet;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.minima.objects.keys.SigningScheme;
import org.minima.utils.json.JSONObject;

public class KeyRow {

	public int mSize;
	public int mDepth;

	public int mUses;
	public int mMaxUses;

	/**
	 * Тип схемы подписи (0=WOTS, 1=SPHINCS+)
	 */
	public int mSchemeType;

	public String 	mModifier;

	public String 	mPublicKey;
	public String 	mPrivateKey;

	public KeyRow(ResultSet zResults) throws SQLException {
		mSize 		= zResults.getInt("size");
		mDepth 		= zResults.getInt("depth");
		mUses 		= zResults.getInt("uses");
		mMaxUses 	= zResults.getInt("maxuses");
		mModifier 	= zResults.getString("modifier");
		mPrivateKey = zResults.getString("privatekey");
		mPublicKey 	= zResults.getString("publickey");

		// Читаем тип схемы. По умолчанию 0 (Winternitz) для обратной совместимости.
		try {
			mSchemeType = zResults.getInt("schemetype");
		} catch (SQLException e) {
			mSchemeType = SigningScheme.SCHEME_WINTERNITZ;
		}
	}

	/**
	 * Обратно-совместимый конструктор (без schemeType — Winternitz)
	 */
	public KeyRow(int zSize, int zDepth, int zUses, int zMaxUses, String zModifier, String zPrivate, String zPublic) {
		this(zSize, zDepth, zUses, zMaxUses, zModifier, zPrivate, zPublic, SigningScheme.SCHEME_WINTERNITZ);
	}

	/**
	 * Конструктор с типом схемы
	 */
	public KeyRow(int zSize, int zDepth, int zUses, int zMaxUses, String zModifier, String zPrivate, String zPublic, int zSchemeType) {
		mSize 		= zSize;
		mDepth 		= zDepth;
		mUses 		= zUses;
		mMaxUses 	= zMaxUses;
		mModifier 	= zModifier;
		mPrivateKey = zPrivate;
		mPublicKey 	= zPublic;
		mSchemeType = zSchemeType;
	}

	public int getSize() {
		return mSize;
	}

	public int getDepth() {
		return mDepth;
	}

	public int getUses() {
		return mUses;
	}

	public int getMaxUses() {
		return mMaxUses;
	}

	public String getModifier() {
		return mModifier;
	}

	public String getPrivateKey() {
		return mPrivateKey;
	}

	public String getPublicKey() {
		return mPublicKey;
	}

	public int getSchemeType() {
		return mSchemeType;
	}

	public JSONObject toJSON() {
		JSONObject ret = new JSONObject();

		ret.put("size", mSize);
		ret.put("depth", mDepth);
		ret.put("uses", mUses);
		ret.put("maxuses", mMaxUses);
		ret.put("modifier", getModifier());
		//ret.put("privatekey", getPrivateKey());
		ret.put("publickey", getPublicKey());
		ret.put("schemetype", mSchemeType);
		ret.put("scheme", mSchemeType == SigningScheme.SCHEME_SPHINCS ? "SPHINCS+" : "WINTERNITZ");

		return ret;
	}
}
