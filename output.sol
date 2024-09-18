pragma solidity ^0.8.20;
import "./examples/example-types.sol";
string constant ACTION_DATA_NOTATION = "ActionData(bytes4 actionTargetSelector,address actionTarget,PolicyData[] actionPolicies)";
bytes32 constant ACTION_DATA_TYPEHASH = keccak256(bytes(ACTION_DATA_NOTATION));
string constant CHAIN_DIGEST_NOTATION = "ChainDigest(uint64 chainId,bytes32 sessionDigest)";
bytes32 constant CHAIN_DIGEST_TYPEHASH = keccak256(
    bytes(CHAIN_DIGEST_NOTATION)
);
string constant CHAIN_SESSION_NOTATION = "ChainSession(uint64 chainId,Session session)";
bytes32 constant CHAIN_SESSION_TYPEHASH = keccak256(
    bytes(CHAIN_SESSION_NOTATION)
);
string constant ERC7739DATA_NOTATION = "ERC7739Data(string[] allowedERC7739Content,PolicyData[] erc1271Policies)";
bytes32 constant ERC7739DATA_TYPEHASH = keccak256(bytes(ERC7739DATA_NOTATION));
string constant ENABLE_SESSION_NOTATION = "EnableSession(uint8 chainDigestIndex,ChainDigest[] hashesAndChainIds,Session sessionToEnable,bytes permissionEnableSig)";
bytes32 constant ENABLE_SESSION_TYPEHASH = keccak256(
    bytes(ENABLE_SESSION_NOTATION)
);
string constant ENUMERABLE_ACTION_POLICY_NOTATION = "EnumerableActionPolicy(mapping(ActionId => Policy ) actionPolicies,mapping(PermissionId => AssociatedArrayLib.Bytes32Array ) enabledActionIds)";
bytes32 constant ENUMERABLE_ACTION_POLICY_TYPEHASH = keccak256(
    bytes(ENUMERABLE_ACTION_POLICY_NOTATION)
);
string constant MULTI_CHAIN_SESSION_NOTATION = "MultiChainSession(ChainSession[] sessionsAndChainIds)";
bytes32 constant MULTI_CHAIN_SESSION_TYPEHASH = keccak256(
    bytes(MULTI_CHAIN_SESSION_NOTATION)
);
string constant POLICY_NOTATION = "Policy(mapping(PermissionId => EnumerableSet.AddressSet ) policyList)";
bytes32 constant POLICY_TYPEHASH = keccak256(bytes(POLICY_NOTATION));
string constant POLICY_DATA_NOTATION = "PolicyData(address policy,bytes initData)";
bytes32 constant POLICY_DATA_TYPEHASH = keccak256(bytes(POLICY_DATA_NOTATION));
string constant SESSION_NOTATION = "Session(ISessionValidator sessionValidator,bytes sessionValidatorInitData,bytes32 salt,PolicyData[] userOpPolicies,ERC7739Data erc7739Policies,ActionData[] actions)";
bytes32 constant SESSION_TYPEHASH = keccak256(bytes(SESSION_NOTATION));
library TypeHashes {
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
    function hashChainSession(
        ChainSession memory chainSession
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    CHAIN_SESSION_TYPEHASH,
                    chainSession.chainId,
                    hashSession(chainSession.session)
                )
            );
    }
    function hashChainSessionArray(
        ChainSession[] memory chainSessionArray
    ) internal pure returns (bytes32) {
        uint256 length = chainSessionArray.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = hashChainSession(chainSessionArray[i]);
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
                    hashSession(enableSession.sessionToEnable),
                    enableSession.permissionEnableSig
                )
            );
    }
    function hashEnumerableActionPolicy(
        EnumerableActionPolicy memory enumerableActionPolicy
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    ENUMERABLE_ACTION_POLICY_TYPEHASH,
                    enumerableActionPolicy.actionPolicies,
                    enumerableActionPolicy.enabledActionIds
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
                    hashChainSessionArray(multiChainSession.sessionsAndChainIds)
                )
            );
    }
    function hashPolicy(Policy memory policy) internal pure returns (bytes32) {
        return keccak256(abi.encode(POLICY_TYPEHASH, policy.policyList));
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
    function hashSession(
        Session memory session
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    SESSION_TYPEHASH,
                    hashISessionValidator(session.sessionValidator),
                    session.sessionValidatorInitData,
                    session.salt,
                    hashPolicyDataArray(session.userOpPolicies),
                    hashERC7739Data(session.erc7739Policies),
                    hashActionDataArray(session.actions)
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
