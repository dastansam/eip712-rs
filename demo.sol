// SPDX-License-Identifier: MIT
pragma solidity ^0.8.6;

struct EnableSession {
    uint8 chainDigestIndex;
    ChainDigest[] hashesAndChainIds;
    SessionConf sessionToEnable;
    bytes permissionEnableSig;
}

struct ChainDigest {
    uint64 chainId;
    bytes32 sessionDigest;
}

struct SessionConf {
    address sessionValidator;
    bytes sessionValidatorInitData;
    bytes32 salt;
    PolicyData[] userOpPolicies;
    ERC7739Data erc7739Policies;
    ActionData[] actions;
}

struct PolicyData {
    address policy;
    bytes initData;
}

struct ActionData {
    bytes4 actionTargetSelector;
    address actionTarget;
    PolicyData[] actionPolicies;
}

struct CustomStructA {
    uint256 a;
    CustomStructB[] bs;
}

struct CustomStructB {
    string b;
    uint256[] c;
}

struct ERC7739Data {
    string[] allowedERC7739Content;
    PolicyData[] erc1271Policies;
}

struct SessionEIP712 {
    address account;
    address smartSession;
    uint8 mode;
    address sessionValidator;
    bytes32 salt;
    bytes sessionValidatorInitData;
    PolicyData[] userOpPolicies;
    ERC7739Data erc7739Policies;
    ActionData[] actions;
}

struct ChainSpecificEIP712 {
    uint64 chainId;
    uint256 nonce;
}

struct MultiChainSession {
    ChainSpecificEIP712[] chainSpecifics;
    SessionEIP712 session;
}
