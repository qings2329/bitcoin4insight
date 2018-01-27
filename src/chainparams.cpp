// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
     
        consensus.BCKINGHeight = 500000;
        consensus.BCKINGdifDec = 26000;
        consensus.powLimit = uint256S("00000000000008ec8e9c4afba2433a085062dc9bdb6eaba190bee41a8733ee9a");
        consensus.powLimitBeforeFork = uint256S("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.premineAddress = "1HtfQehopfz43KWmiFgd2jC9jPEovMpFBX";

        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141 and BIP143)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; // Never / undefined

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xaf;
        pchMessageStart[1] = 0x32;
        pchMessageStart[2] = 0x16;
        pchMessageStart[3] = 0x16;
        nDefaultPort = 16333;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
        assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

//        // Note that of those with the service bits flag, most only support a subset of possible options
//        vSeeds.emplace_back("seed.bitcoin.sipa.be", true); // Pieter Wuille, only supports x1, x5, x9, and xd
//        vSeeds.emplace_back("dnsseed.bluematt.me", true); // Matt Corallo, only supports x9
//        vSeeds.emplace_back("dnsseed.bitcoin.dashjr.org", false); // Luke Dashjr
//        vSeeds.emplace_back("seed.bitcoinstats.com", true); // Christian Decker, supports x1 - xf
//        vSeeds.emplace_back("seed.bitcoin.jonasschnelli.ch", true); // Jonas Schnelli, only supports x1, x5, x9, and xd
//        vSeeds.emplace_back("seed.btc.petertodd.org", true); // Peter Todd, only supports x1, x5, x9, and xd

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
              (0, uint256S("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"))
              (10000, uint256S("07d4b1019c4d88e5404c5da3ae8d6850a4a53cb34d095cd0813481504378348b"))
              (20000, uint256S("0be1c3dbcc40fb8f2169f5c25ffa3e23aa8c731fca55447b942a691f5bda8fea"))
              (30000, uint256S("07d8f2d440c985fa069eff4ff7df0371e509613d69a8e31738d530e00e34e0f9"))
              (40000, uint256S("0e358a120f469b2d132ae53c0e59b88252a41b39140bd34d598c09a1f833a41b"))
              (50000, uint256S("0f5dd991bcddbb15ac08be02a567f08487c1119a13755001c418984eff7fde1b"))
              (60000, uint256S("05bc15b39585d991e7b271e74eba2fa1d3692c9fd4df6b3ea72efe5beaab6428"))
              (70000, uint256S("0fad853074bbf75b9adf6ec2c63f1d08666daafc1bed613ee2cbb9a03218e633"))
              (80000, uint256S("0ab2fac7c0cce6df25d7ab0f4d2d96efd6d8f5ec7d504e5dc5fae93a78b593a4"))
              (90000, uint256S("0aa81fb8e09d2885ecd8af4a7b82402ac96b4a7e95471cbf7e183415a896a2c2"))
              (100000, uint256S("07de29fea3d9abb2ad108e0caab5b467e1b1ba7771bd731b0486041427e9affa"))
              (110000, uint256S("02ba8b755d0836e6f4e789c12a671a76d6133affa6e60df9a9787553bf1b8780"))
              (120000, uint256S("00fb3cc4c26e5901a08156ebf290a41d8d68e0d47d774ce83385427ec929ddbc"))
              (130000, uint256S("0637549bafcd969630dd90f3fb8627b49df1a6f79e763c5a85bc4b1ecd74eb5c"))
              (140000, uint256S("02897de380a379e828e1ef12eee8fb4fb63a7f486c7b4dbca9690745c0bf0446"))
              (150000, uint256S("00e91f045ea4c5be3a6c879ad025b873ce8a2d10c2072dd5ccf100857240caca"))
              (160000, uint256S("0cf698f730e5d45c75f5b9f8a4d98adba5e03f7b0f74415ff976002409606b61"))
              (170000, uint256S("03cbb6eae20cead1b9df5a4c38cb1be12526660d197b528f8c1420b1fec91b4e"))
              (180000, uint256S("05c92ddea8ef9d46b64c11545599c74556fd7a1033280e056c6029e5e2443213"))
              (190000, uint256S("096285e35639cd24fd373f629ac94e6b6822e2a0e97d24b7ee5a9ec613073870"))
              (200000, uint256S("0d95ea0f0dded82b3d606fabb5fdfcf8cfde811e080a3aaad61f8701664acc73"))
              (210000, uint256S("0361fd44a03b3e4c61b439bac7d816c305c1acf0330f100886e2d43b75d8d282"))
              (220000, uint256S("08388b56fd7358a1081a84e11c219c2cf8de4fdd42e6598a0d42b87f601e2d19"))
              (230000, uint256S("09b43838294043ad3df831470ae01317feed2b2d8d1e3cdb918e42ba5b9f1822"))
              (240000, uint256S("084f704b2accf7fb0018843bb19fbeb08e3f5b46cdae5807d7ca5bf07dd31a45"))
              (250000, uint256S("01aec042b4ed8b6541a5f686f9a177e54ca00627575547de0181165b13aff05f"))
              (260000, uint256S("09d25283e98855ca60d64106c529730ce8e5f23d0c449c76c7a1cf975eefbe8b"))
              (270000, uint256S("08a758de4a88af8a404d5b4189183352714db90bb7c24d2d3455e0ce40e65df6"))
              (280000, uint256S("056d8a1313b2cabb0621a8dd5959d58a50b11c336888547c2501d8ed24869dc7"))
              (290000, uint256S("0866f3488a491d99e2e31c14a8f5fa4e57bdd8c0255b323acf5e4cb315686f17"))
              (300000, uint256S("0f514c278d0137ec50de44f07174710946051fbaf4c2cf1f4eea8659f4152e5c"))
              (310000, uint256S("040384214f83cc9286d3abcc220cf35ad664c8e4f4ebea5e46cf3528a91e9088"))
              (320000, uint256S("069a8fa82e133cb96efeb2b03e0576e620e08c5d86b88ffe8f1d9a7932a10be3"))
              (330000, uint256S("08e63f1e82dcaaa5275a627a08d9c1fe68a7728869b69a5d05a6d5e8ceba833f"))
              (340000, uint256S("0d602078276cd9248dd869ad1e200321c98a1eedaf957b97d66aa78c405a3c51"))
              (350000, uint256S("088f1836735c85cf666b6eac95f40da2817aa0fabf5e875fa930a779e884ee09"))
              (360000, uint256S("05b0de671776d0b005c7f43b9320fb4fab5ca624f3502fb01a3ca2a22ddc65b0"))
              (370000, uint256S("048f05305d3b40b7c672af476331a7dd446eaa457a4e673bb1d03130f67a37d1"))
              (380000, uint256S("0c097b43fd2d8b76cda9e2cb2fdf3b8555a427f19f1f4c0c5bdf853395bdc293"))
              (390000, uint256S("01ab59f90473db47b74fd56492536369fe035066a7d6d876bd8db94e8bf9af70"))
              (400000, uint256S("0ac0d23d9319c56375ead881375ff92d767069469c127d960bfef5577cfff3c4"))
              (410000, uint256S("021d8f8987605c1fb6c3bcd7f9fd9a438d7acfe284295d8b20c682dfc41e5b8f"))
              (420000, uint256S("007eac74b390991ff5882ecb685f1c79c8b19b8f128d637badfea20aa7bed4d8"))
              (430000, uint256S("09f35059f62bc08105d3f75e1396f666f704f246ce26e275ab8bd1a374f9533c"))
              (440000, uint256S("09a9dff6ff23af7aaf4ff7b4b3086837b1111ff21086b4002ac8b969fc64d87a"))
              (450000, uint256S("0d4b15c1a148bed9167b38b26ba8b3f7500063f61680e60d8fe901f964b12592"))
              (460000, uint256S("0eab07ca36ab5fd7d54db940605832a82168e572b26c7147a19ebe1137344700"))
              (470000, uint256S("0a84df73e418581beedff3f411249079e596b3b22f5eb2394d8e17e66ff06335"))
              (480000, uint256S("0f8a71487b67ee464e62aca52ecb96ce007da949316e8a5c3003dc40629c8991"))
              (490000, uint256S("0f527fbbe25f1cd5d01b5c1d7fab8718b59b199ae8e29df2c9f8953c684b3746"))
              (500000, uint256S("000000000000007848d3c75b228e873f62aa35d65dfb730b4ba1b57b279d6ea7")),
              1515235845, // * UNIX timestamp of last checkpoint block
              491710,   // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
              3     // * estimated number of transactions per day after checkpoint
        };

    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
      
        consensus.BCKINGHeight = 1255842; 
        consensus.BCKINGdifDec = 10;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimitBeforeFork = uint256S("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141 and BIP143)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        consensus.premineAddress = "mkf1kNYgNjkQqARudKairecZxyUBpzFCFd";

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xa7;
        pchMessageStart[2] = 0x4d;
        pchMessageStart[3] = 0x22;
        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1296688602, 414098458, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"));
        assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        // vSeeds.emplace_back("testnet-seed.bitcoin.jonasschnelli.ch", true);
        // vSeeds.emplace_back("seed.tbtc.petertodd.org", true);
        // vSeeds.emplace_back("testnet-seed.bluematt.me", false);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 546, uint256S("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")),
            1337966069,
            1488,
            300
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256();
       
        consensus.BCKINGHeight = 200; 
        consensus.BCKINGdifDec = 100;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimitBeforeFork = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        pchMessageStart[0] = 0x5a;
        pchMessageStart[1] = 0xf6;
        pchMessageStart[2] = 0x3b;
        pchMessageStart[3] = 0xe5;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"));
        assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")),
            0,
            0,
            0
        };
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}
 
