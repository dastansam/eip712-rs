pragma solidity ^0.8.20;
import "./demo.sol";
library TypeHashes {
    string constant ACTION_DATA_NOTATION =
        "ActionData(bytes4 actionTargetSelector,address actionTarget,PolicyData[] actionPolicies)";
    bytes32 constant ACTION_DATA_TYPEHASH =
        keccak256(bytes(ACTION_DATA_NOTATION));
    string constant CHAIN_DIGEST_NOTATION =
        "ChainDigest(uint64 chainId,bytes32 sessionDigest)";
    bytes32 constant CHAIN_DIGEST_TYPEHASH =
        keccak256(bytes(CHAIN_DIGEST_NOTATION));
    string constant CHAIN_SPECIFIC_EIP712_NOTATION =
        "ChainSpecificEIP712(uint64 chainId,uint256 nonce)";
    bytes32 constant CHAIN_SPECIFIC_EIP712_TYPEHASH =
        keccak256(bytes(CHAIN_SPECIFIC_EIP712_NOTATION));
    string constant CUSTOM_STRUCT_A_NOTATION =
        "CustomStructA(uint256 a,CustomStructB[] bs)";
    bytes32 constant CUSTOM_STRUCT_A_TYPEHASH =
        keccak256(bytes(CUSTOM_STRUCT_A_NOTATION));
    string constant CUSTOM_STRUCT_B_NOTATION =
        "CustomStructB(string b,uint256[] c)";
    bytes32 constant CUSTOM_STRUCT_B_TYPEHASH =
        keccak256(bytes(CUSTOM_STRUCT_B_NOTATION));
    string constant ERC7739DATA_NOTATION =
        "ERC7739Data(string[] allowedERC7739Content,PolicyData[] erc1271Policies)";
    bytes32 constant ERC7739DATA_TYPEHASH =
        keccak256(bytes(ERC7739DATA_NOTATION));
    string constant ENABLE_SESSION_NOTATION =
        "EnableSession(uint8 chainDigestIndex,ChainDigest[] hashesAndChainIds,SessionConf sessionToEnable,bytes permissionEnableSig)";
    bytes32 constant ENABLE_SESSION_TYPEHASH =
        keccak256(bytes(ENABLE_SESSION_NOTATION));
    string constant MULTI_CHAIN_SESSION_NOTATION =
        "MultiChainSession(ChainSpecificEIP712[] chainSpecifics,SessionEIP712 session)";
    bytes32 constant MULTI_CHAIN_SESSION_TYPEHASH =
        keccak256(bytes(MULTI_CHAIN_SESSION_NOTATION));
    string constant POLICY_DATA_NOTATION =
        "PolicyData(address policy,bytes initData)";
    bytes32 constant POLICY_DATA_TYPEHASH =
        keccak256(bytes(POLICY_DATA_NOTATION));
    string constant SESSION_CONF_NOTATION =
        "SessionConf(address sessionValidator,bytes sessionValidatorInitData,bytes32 salt,PolicyData[] userOpPolicies,ERC7739Data erc7739Policies,ActionData[] actions)";
    bytes32 constant SESSION_CONF_TYPEHASH =
        keccak256(bytes(SESSION_CONF_NOTATION));
    string constant SESSION_EIP712_NOTATION =
        "SessionEIP712(address account,address smartSession,uint8 mode,address sessionValidator,bytes32 salt,bytes sessionValidatorInitData,PolicyData[] userOpPolicies,ERC7739Data erc7739Policies,ActionData[] actions)";
    bytes32 constant SESSION_EIP712_TYPEHASH =
        keccak256(bytes(SESSION_EIP712_NOTATION));
    function hashActionData(
        ActionData memory actionData
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    ACTION_DATA_TYPEHASH,
                    actionData.actionTargetSelector,
                    actionData.actionTarget,
                    hashPolicyDataArray(actionData.actionPolicies)
                )
            );
    }
    function hashActionDataArray(
        ActionData[] memory actionDataArray
    ) internal pure returns (bytes32) {
        uint256 length = actionDataArray.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = hashActionData(actionDataArray[i]);
        }
        return keccak256(abi.encodePacked(hashes));
    }
    function hashChainDigest(
        ChainDigest memory chainDigest
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    CHAIN_DIGEST_TYPEHASH,
                    chainDigest.chainId,
                    chainDigest.sessionDigest
                )
            );
    }
    function hashChainDigestArray(
        ChainDigest[] memory chainDigestArray
    ) internal pure returns (bytes32) {
        uint256 length = chainDigestArray.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = hashChainDigest(chainDigestArray[i]);
        }
        return keccak256(abi.encodePacked(hashes));
    }
    function hashChainSpecificEIP712(
        ChainSpecificEIP712 memory chainSpecificEIP712
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    CHAIN_SPECIFIC_EIP712_TYPEHASH,
                    chainSpecificEIP712.chainId,
                    chainSpecificEIP712.nonce
                )
            );
    }
    function hashChainSpecificEIP712Array(
        ChainSpecificEIP712[] memory chainSpecificEIP712Array
    ) internal pure returns (bytes32) {
        uint256 length = chainSpecificEIP712Array.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = hashChainSpecificEIP712(chainSpecificEIP712Array[i]);
        }
        return keccak256(abi.encodePacked(hashes));
    }
    function hashCustomStructA(
        CustomStructA memory customStructA
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    CUSTOM_STRUCT_A_TYPEHASH,
                    customStructA.a,
                    hashCustomStructBArray(customStructA.bs)
                )
            );
    }
    function hashCustomStructB(
        CustomStructB memory customStructB
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    CUSTOM_STRUCT_B_TYPEHASH,
                    customStructB.b,
                    customStructB.c
                )
            );
    }
    function hashCustomStructBArray(
        CustomStructB[] memory customStructBArray
    ) internal pure returns (bytes32) {
        uint256 length = customStructBArray.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = hashCustomStructB(customStructBArray[i]);
        }
        return keccak256(abi.encodePacked(hashes));
    }
    function hashERC7739Data(
        ERC7739Data memory eRC7739Data
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    ERC7739DATA_TYPEHASH,
                    hashStringArray(eRC7739Data.allowedERC7739Content),
                    hashPolicyDataArray(eRC7739Data.erc1271Policies)
                )
            );
    }
    function hashEnableSession(
        EnableSession memory enableSession
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    ENABLE_SESSION_TYPEHASH,
                    enableSession.chainDigestIndex,
                    hashChainDigestArray(enableSession.hashesAndChainIds),
                    enableSession.sessionToEnable,
                    enableSession.permissionEnableSig
                )
            );
    }
    function hashMultiChainSession(
        MultiChainSession memory multiChainSession
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    MULTI_CHAIN_SESSION_TYPEHASH,
                    hashChainSpecificEIP712Array(
                        multiChainSession.chainSpecifics
                    ),
                    multiChainSession.session
                )
            );
    }
    function hashPolicyData(
        PolicyData memory policyData
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    POLICY_DATA_TYPEHASH,
                    policyData.policy,
                    policyData.initData
                )
            );
    }
    function hashPolicyDataArray(
        PolicyData[] memory policyDataArray
    ) internal pure returns (bytes32) {
        uint256 length = policyDataArray.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = hashPolicyData(policyDataArray[i]);
        }
        return keccak256(abi.encodePacked(hashes));
    }
    function hashSessionConf(
        SessionConf memory sessionConf
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    SESSION_CONF_TYPEHASH,
                    sessionConf.sessionValidator,
                    sessionConf.sessionValidatorInitData,
                    sessionConf.salt,
                    hashPolicyDataArray(sessionConf.userOpPolicies),
                    sessionConf.erc7739Policies,
                    hashActionDataArray(sessionConf.actions)
                )
            );
    }
    function hashSessionEIP712(
        SessionEIP712 memory sessionEIP712
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    SESSION_EIP712_TYPEHASH,
                    sessionEIP712.account,
                    sessionEIP712.smartSession,
                    sessionEIP712.mode,
                    sessionEIP712.sessionValidator,
                    sessionEIP712.salt,
                    sessionEIP712.sessionValidatorInitData,
                    hashPolicyDataArray(sessionEIP712.userOpPolicies),
                    sessionEIP712.erc7739Policies,
                    hashActionDataArray(sessionEIP712.actions)
                )
            );
    }
    function hashStringArray(
        string[] memory stringArray
    ) internal pure returns (bytes32) {
        uint256 length = stringArray.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = keccak256(abi.encodePacked(stringArray[i]));
        }
        return keccak256(abi.encodePacked(hashes));
    }
}
