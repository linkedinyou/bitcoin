// Copyright (c) 2009-2010 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.


// secp160k1
// const unsigned int PRIVATE_KEY_SIZE = 192;
// const unsigned int PUBLIC_KEY_SIZE  = 41;
// const unsigned int SIGNATURE_SIZE   = 48;
//
// secp192k1
// const unsigned int PRIVATE_KEY_SIZE = 222;
// const unsigned int PUBLIC_KEY_SIZE  = 49;
// const unsigned int SIGNATURE_SIZE   = 57;
//
// secp224k1
// const unsigned int PRIVATE_KEY_SIZE = 250;
// const unsigned int PUBLIC_KEY_SIZE  = 57;
// const unsigned int SIGNATURE_SIZE   = 66;
//
// secp256k1:
// const unsigned int PRIVATE_KEY_SIZE = 279;
// const unsigned int PUBLIC_KEY_SIZE  = 65;
// const unsigned int SIGNATURE_SIZE   = 72;
//
// see www.keylength.com
// script supports up to 75 for single byte push

int static inline EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *order = NULL;
    EC_POINT *pub_key = NULL;

    if (!eckey) return 0;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);

    if ((order = BN_new()) == NULL) goto err;
    if ((ctx = BN_CTX_new()) == NULL) goto err;

    if (!EC_GROUP_get_order(group, order, ctx)) goto err;

    pub_key = EC_POINT_new(group);

    if (pub_key == NULL) goto err;

    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx)) goto err;

    EC_KEY_set_private_key(eckey,priv_key);
    EC_KEY_set_public_key(eckey,pub_key);

    ok=1;

err:

    if (order)
        BN_free(order);
    if (pub_key)
        EC_POINT_free(pub_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);

    return(ok);
}

int static inline ECDSA_SIG_recover_key(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid)
{
    if (!eckey) return 0;

    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *cofactor = NULL;
    BIGNUM *x = NULL;
    BIGNUM *e = NULL;
    BIGNUM *order = NULL;
    BIGNUM *sor = NULL;
    BIGNUM *eor = NULL;
    EC_POINT *R = NULL;
    EC_POINT *O = NULL;
    BIGNUM *rr = NULL;
    int n = 0;
    int i = recid / 2;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
    
    BN_CTX_start(ctx);
    cofactor = BN_CTX_get(ctx);
    if (!EC_GROUP_get_cofactor(group, cofactor, ctx)) { ret = -2; goto err; }
    order = BN_CTX_get(ctx);
    if (!EC_GROUP_get_order(group, order, ctx)) { ret = -3; goto err; }
    
    x = BN_CTX_get(ctx);
    BN_copy(x, cofactor);
    BN_mul_word(x, i);
    BN_mod_add(x, x, ecsig->r, order, ctx);
    
    if ((R = EC_POINT_new(group)) == NULL) { ret = -4; goto err; }
    
    EC_POINT_set_compressed_coordinates_GFp(group, R, x, 0, ctx);
    
    if ((O = EC_POINT_new(group)) == NULL) { ret = -5; goto err; }
    
    EC_POINT_mul(group, O, NULL, R, cofactor, ctx);
    
    if (!EC_POINT_is_at_infinity(group, O)) { ret = -6; goto err; }
    
    if (recid & 1) EC_POINT_invert(group, R, ctx);
    
    n = BN_num_bits(order);
    e = BN_CTX_get(ctx);
    BN_bin2bn(msg, msglen, e);
    if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
    BN_set_negative(e, 1);
    
    rr = BN_CTX_get(ctx);
    BN_mod_inverse(rr, ecsig->r, order, ctx);
    sor = BN_CTX_get(ctx);
    BN_mod_mul(sor, ecsig->s, rr, order, ctx);
    eor = BN_CTX_get(ctx);
    BN_mod_mul(eor, e, rr, order, ctx);

    EC_POINT_mul(group, O, eor, R, sor, ctx);

    EC_KEY_set_public_key(eckey, O);
    
    ret = 1;
    
err:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (R != NULL) EC_POINT_free(R);
    if (O != NULL) EC_POINT_free(O);
    return ret;
}

class key_error : public std::runtime_error
{
public:
    explicit key_error(const std::string& str) : std::runtime_error(str) {}
};


// secure_allocator is defined in serialize.h
typedef vector<unsigned char, secure_allocator<unsigned char> > CPrivKey;



class CKey
{
protected:
    EC_KEY* pkey;
    bool fSet;

public:
    CKey()
    {
        pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (pkey == NULL)
            throw key_error("CKey::CKey() : EC_KEY_new_by_curve_name failed");
        fSet = false;
    }

    CKey(const CKey& b)
    {
        pkey = EC_KEY_dup(b.pkey);
        if (pkey == NULL)
            throw key_error("CKey::CKey(const CKey&) : EC_KEY_dup failed");
        fSet = b.fSet;
    }

    CKey& operator=(const CKey& b)
    {
        if (!EC_KEY_copy(pkey, b.pkey))
            throw key_error("CKey::operator=(const CKey&) : EC_KEY_copy failed");
        fSet = b.fSet;
        return (*this);
    }

    ~CKey()
    {
        EC_KEY_free(pkey);
    }

    bool IsNull() const
    {
        return !fSet;
    }

    void MakeNewKey()
    {
        if (!EC_KEY_generate_key(pkey))
            throw key_error("CKey::MakeNewKey() : EC_KEY_generate_key failed");
        fSet = true;
    }

    bool SetPrivKey(const CPrivKey& vchPrivKey)
    {
        const unsigned char* pbegin = &vchPrivKey[0];
        if (!d2i_ECPrivateKey(&pkey, &pbegin, vchPrivKey.size()))
            return false;
        fSet = true;
        return true;
    }

    CPrivKey GetPrivKey() const
    {
        unsigned int nSize = i2d_ECPrivateKey(pkey, NULL);
        if (!nSize)
            throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey failed");
        CPrivKey vchPrivKey(nSize, 0);
        unsigned char* pbegin = &vchPrivKey[0];
        if (i2d_ECPrivateKey(pkey, &pbegin) != nSize)
            throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey returned unexpected size");
        return vchPrivKey;
    }

    bool SetPubKey(const vector<unsigned char>& vchPubKey)
    {
        const unsigned char* pbegin = &vchPubKey[0];
        if (!o2i_ECPublicKey(&pkey, &pbegin, vchPubKey.size()))
            return false;
        fSet = true;
        return true;
    }

    vector<unsigned char> GetPubKey() const
    {
        unsigned int nSize = i2o_ECPublicKey(pkey, NULL);
        if (!nSize)
            throw key_error("CKey::GetPubKey() : i2o_ECPublicKey failed");
        vector<unsigned char> vchPubKey(nSize, 0);
        unsigned char* pbegin = &vchPubKey[0];
        if (i2o_ECPublicKey(pkey, &pbegin) != nSize)
            throw key_error("CKey::GetPubKey() : i2o_ECPublicKey returned unexpected size");
        return vchPubKey;
    }

    bool Sign(uint256 hash, vector<unsigned char>& vchSig)
    {
        vchSig.clear();
        unsigned char pchSig[10000];
        unsigned int nSize = 0;
        if (!ECDSA_sign(0, (unsigned char*)&hash, sizeof(hash), pchSig, &nSize, pkey))
            return false;
        vchSig.resize(nSize);
        memcpy(&vchSig[0], pchSig, nSize);
        return true;
    }

    bool Verify(uint256 hash, const vector<unsigned char>& vchSig)
    {
        // -1 = error, 0 = bad sig, 1 = good
        if (ECDSA_verify(0, (unsigned char*)&hash, sizeof(hash), &vchSig[0], vchSig.size(), pkey) != 1)
            return false;
        cout << "Verification of signature: recid=" << RecoverPubKey(hash, vchSig) << endl;
        return true;
    }
    
    int RecoverPubKey(uint256 hash, const vector<unsigned char>& vchSig)
    {
        CKey key;
	ECDSA_SIG *sig = ECDSA_SIG_new();
	const unsigned char *pvchSig = &vchSig[0];
	d2i_ECDSA_SIG(&sig, &pvchSig, vchSig.size());
	key.fSet = true;
	for (int i = 0; i<4; i++)
	{
	    int ret = ECDSA_SIG_recover_key(key.pkey, sig, (unsigned char*)&hash, sizeof(hash), i);
	    cout << "try " << i << ": ret=" << ret << endl;
	    if (ret==1)
	        if (key.GetPubKey() == this->GetPubKey())
	            return i;
	}
        return -1;
    }

    static bool Sign(const CPrivKey& vchPrivKey, uint256 hash, vector<unsigned char>& vchSig)
    {
        CKey key;
        if (!key.SetPrivKey(vchPrivKey))
            return false;
        return key.Sign(hash, vchSig);
    }

    static bool Verify(const vector<unsigned char>& vchPubKey, uint256 hash, const vector<unsigned char>& vchSig)
    {
        CKey key;
        if (!key.SetPubKey(vchPubKey))
            return false;
        return key.Verify(hash, vchSig);
    }
};
