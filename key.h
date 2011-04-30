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

#define LOOPSIZE 10000

struct ec_point_st {
const EC_METHOD *meth;
/* All members except 'meth' are handled by the method functions,
 * even if they appear generic */
BIGNUM X;
BIGNUM Y;
BIGNUM Z; /* Jacobian projective coordinates:
           * (X, Y, Z)  represents  (X/Z^2, Y/Z^3)  if  Z != 0 */
int Z_is_one; /* enable optimized point arithmetics for special case */
} /* EC_POINT */;

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

int static inline ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check)
{
    if (!eckey) return 0;

    int ret = 0;
    BN_CTX *ctx = NULL;
    
    BIGNUM *x = NULL;
    BIGNUM *e = NULL;
    BIGNUM *order = NULL;
    BIGNUM *sor = NULL;
    BIGNUM *eor = NULL;
    BIGNUM *field = NULL;
    EC_POINT *R = NULL;
    EC_POINT *O = NULL;
    EC_POINT *Q = NULL;
    BIGNUM *rr = NULL;
    BIGNUM *zero = NULL;
    int n = 0;
    int i = recid / 2;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }

    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    if (!EC_GROUP_get_order(group, order, ctx)) { ret = -3; goto err; }
//    cout << "order="; BN_print_fp(stdout, order); cout << endl;

    x = BN_CTX_get(ctx);
    if (!BN_copy(x, order)) { ret=-4; goto err; }
    if (!BN_mul_word(x, i)) { ret=-5; goto err; }
//    cout << "i*order="; BN_print_fp(stdout, x); cout << endl;
//    if (!BN_mod_add(x, x, ecsig->r, order, ctx)) { ret=-6; goto err; }
    if (!BN_add(x, x, ecsig->r)) { ret=-6; goto err; }
//    cout << "i*order+r=x="; BN_print_fp(stdout, x); cout << endl;

    field = BN_CTX_get(ctx);
    if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx));
    if (BN_cmp(x, field) >= 0) { ret=-22; goto err; }

    if ((R = EC_POINT_new(group)) == NULL) { ret = -7; goto err; }
    
    if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret=-8; goto err; }
//    cout << "R: (X="; BN_print_fp(stdout,&R->X); cout << ",Y="; BN_print_fp(stdout,&R->Y); cout << ",Z="; BN_print_fp(stdout,&R->Z); cout << ")\n";

    if (check)
    {
        if ((O = EC_POINT_new(group)) == NULL) { ret = -9; goto err; }

        if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret=-10; goto err; }
//    cout << "O: (X="; BN_print_fp(stdout,&O->X); cout << ",Y="; BN_print_fp(stdout,&O->Y); cout << ",Z="; BN_print_fp(stdout,&O->Z); cout << ")\n";
    
        if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
    }
    
//    if (recid & 1) if (!EC_POINT_invert(group, R, ctx)) { ret=-12; goto err; }
    
    if ((Q = EC_POINT_new(group)) == NULL) { ret = -13; goto err; }
    n = EC_GROUP_get_degree(group);
    e = BN_CTX_get(ctx);
    if (!BN_bin2bn(msg, msglen, e)) { ret=-14; goto err; }
//    cout << "key recovery: n=" << n << " msglen=" << (8*msglen) << endl;
    if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
//    cout << "e="; BN_print_fp(stdout, e); cout << endl;
    zero = BN_CTX_get(ctx);
    if (!BN_zero(zero)) { ret=-21; goto err; }
    if (!BN_mod_sub(e, zero, e, order, ctx)) { ret=-15; goto err; }
//    cout << "-e="; BN_print_fp(stdout, e); cout << endl;
    
    
    rr = BN_CTX_get(ctx);
    if (!BN_mod_inverse(rr, ecsig->r, order, ctx)) { ret=-16; goto err; }
    sor = BN_CTX_get(ctx);
    if (!BN_mod_mul(sor, ecsig->s, rr, order, ctx)) { ret=-17; goto err; }
//    cout << "s/r="; BN_print_fp(stdout, sor); cout << endl;
    eor = BN_CTX_get(ctx);
    if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret=-18; goto err; }
//    cout << "-e/r="; BN_print_fp(stdout, eor); cout << endl;

    if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret=-19; goto err; }
//    cout << "Q: (X="; BN_print_fp(stdout,&Q->X); cout << ",Y="; BN_print_fp(stdout,&Q->Y); cout << ",Z="; BN_print_fp(stdout,&Q->Z); cout << ")\n";

    if (!EC_KEY_set_public_key(eckey, Q)) { ret=-20; goto err; }
    
    ret = 1;
    
err:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (R != NULL) EC_POINT_free(R);
    if (O != NULL) EC_POINT_free(O);
    if (Q != NULL) EC_POINT_free(Q);
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
    
    bool CompactSign(uint256 hash, vector<unsigned char>& vchSig)
    {
        bool fOk = false;
        ECDSA_SIG *sig = ECDSA_do_sign((unsigned char*)&hash, sizeof(hash), pkey);
        vchSig.clear();
        vchSig.resize(65,0);
        if (sig==NULL)
            return false;
        int nBitsR = BN_num_bits(sig->r);
        int nBitsS = BN_num_bits(sig->s);
        if (nBitsR <= 256 && nBitsS <= 256)
        {
            int nRecId = -1;
            for (int i=0; i<4; i++)
            {
                CKey keyRec;
                keyRec.fSet = true;
                if (ECDSA_SIG_recover_key_GFp(keyRec.pkey, sig, (unsigned char*)&hash, sizeof(hash), i, 1) == 1)
                    if (keyRec.GetPubKey() == this->GetPubKey())
                    {
                        nRecId = i;
                        break;
                    }
            }
            
            if (nRecId == -1)
                throw key_error("CKEy::SignCompact() : unable to construct recoverable key");
            
            vchSig[0] = nRecId+27;
            BN_bn2bin(sig->r,&vchSig[33-(nBitsR+7)/8]);
            BN_bn2bin(sig->s,&vchSig[65-(nBitsS+7)/8]);
            fOk = true;
        }
        ECDSA_SIG_free(sig);
        return fOk;
    }

    bool FromCompactSignature(uint256 hash, const vector<unsigned char>& vchSig)
    {
        if (vchSig.size() != 65)
            return false;
        if (vchSig[0]<27 || vchSig[0]>=31)
            return false;
        ECDSA_SIG *sig = ECDSA_SIG_new();
        BN_bin2bn(&vchSig[1],32,sig->r);
        BN_bin2bn(&vchSig[33],32,sig->s);

        EC_KEY_free(pkey);
        pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (ECDSA_SIG_recover_key_GFp(pkey, sig, (unsigned char*)&hash, sizeof(hash), vchSig[0] - 27, 0) == 1)
        {
            fSet = true;
            ECDSA_SIG_free(sig);
            return true;
        }
        return false;
    }
    
    bool Verify(uint256 hash, const vector<unsigned char>& vchSig)
    {
        // -1 = error, 0 = bad sig, 1 = good
        unsigned int nStart = GetTimeMillis();
        for (int k=0; k<LOOPSIZE; k++)
        {
            if (ECDSA_verify(0, (unsigned char*)&hash, sizeof(hash), &vchSig[0], vchSig.size(), pkey) != 1)
                return false;
        }
        nStart = GetTimeMillis() - nStart;
        cout << "Verification of " << LOOPSIZE << " signatures took " << strprintf("%15"PRI64d"ms", nStart) << endl;
        cout << "Verification of signature: recid=" << RecoverPubKey(hash, vchSig) << endl;
        return true;
    }
    
    int RecoverPubKey(uint256 hash, const vector<unsigned char>& vchSig)
    {
        static uint256 testhash=uint256("bb07b6c133446afe1894f3758d315c928f4d5960195571bfcd271e3d81909d9c");
        CKey key;
	ECDSA_SIG *sig = ECDSA_SIG_new();
	const unsigned char *pvchSig = &vchSig[0];
	d2i_ECDSA_SIG(&sig, &pvchSig, vchSig.size());
	key.fSet = true;
        vector<unsigned char> vchCSig;
        vchCSig.resize(65,0);
        int nRet = -1;
	for (int i = 0; i<4; i++)
	{
	    int ret = ECDSA_SIG_recover_key_GFp(key.pkey, sig, (unsigned char*)&hash, sizeof(hash), i, 1);
	    if (ret==1)
	        if (key.GetPubKey() == this->GetPubKey())
	            nRet = i;
	}
        vchCSig[0] = 27+nRet;
        int nBitsR = BN_num_bits(sig->r);
        int nBitsS = BN_num_bits(sig->s);
        BN_bn2bin(sig->r,&vchCSig[33-(nBitsR+7)/8]);
        BN_bn2bin(sig->s,&vchCSig[65-(nBitsS+7)/8]);

        unsigned int nStart = GetTimeMillis();
        for (int k=0; k<LOOPSIZE; k++)
        {
            if (!key.FromCompactSignature(hash, vchCSig))
            {
                cout << "UNABLE TO RECOVER PUBLIC KEY FROM COMPACT SIGNATURE " << EncodeBase58Check(vchCSig) << endl;
                return false;
            }
        }
        nStart = GetTimeMillis() - nStart;
        if (key.GetPubKey() == this->GetPubKey())
        {
            cout << "succesfully recoved key using compact signature " << EncodeBase58Check(vchCSig) << endl;
        }
        else
        {
            cout << "FAILURE... incorrectly recovered key" << endl;
        }
        cout << "Recovery of " << LOOPSIZE << " keys took " << strprintf("%15"PRI64d"ms", nStart) << endl;
        
        for (int idx=0; idx<4; idx++)
        {
            CKey ekey;
            int res = ECDSA_SIG_recover_key_GFp(ekey.pkey, sig, (unsigned char*)&testhash, sizeof(testhash), idx, 0);
            if (res == 1)
            {
                CKey ekey2;
                int res2 = ECDSA_SIG_recover_key_GFp(ekey2.pkey, sig, (unsigned char*)&testhash, sizeof(testhash), idx, 1);
                if (res2 != 1)
                    cout << "WOAH! recovery from random digest works, but not when checking..." << endl;
                int res3 = ECDSA_do_verify((unsigned char*)&testhash, sizeof(testhash), sig, ekey.pkey);
                if (res3 != 1)
                    cout << "WOAH! recovery from random digest works, but signature is invalid" << endl;
                if (res2 == 1 && res3 == 1)
                    cout << "nice, key recovered from random digest is valid" << endl;
            }
            else
                cout << "... cannot recover from random digest possible" << endl;
        }
        return nRet;
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
