# eip712-rs

CLI tool that generates EIP712 specific constants and functions for all `struct`s in a given Solidity source file.

## Usage

```bash
cargo run generate --input <input-solidity-file> --output <output-rs-file>
```

## Example

Source file:
```solidity
struct CustomStructA {
    uint256 a;
    CustomStructB[] bs;
}

struct CustomStructB {
    string b;
}
```

Result:

```solidity
lib TypeHashes {
    string constant CUSTOM_STRUCT_A_NOTATION = "CustomStructA(uint256 a,CustomStructB[] bs)";
    bytes32 constant CUSTOM_STRUCT_A_TYPEHASH = keccak256(bytes(CUSTOM_STRUCT_A_NOTATION));
    string constant CUSTOM_STRUCT_B_NOTATION = "CustomStructB(string b)";
    bytes32 constant CUSTOM_STRUCT_B_TYPEHASH = keccak256(bytes(CUSTOM_STRUCT_B_NOTATION));

    function hashCustomStructA(CustomStructA memory customStructA) internal pure returns (bytes32) {
        return keccak256(abi.encode(customStructA.a, customStructA.bs.hashCustomStructBArray()));
    }

    function hashCustomStructB(CustomStructB memory customStructB) internal pure returns (bytes32) {
        return keccak256(abi.encode(customStructB.b));
    }

    function hashCustomStructBArray(CustomStructB[] memory customStructBArray) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](customStructBArray.length);
        for (uint256 i = 0; i < customStructBArray.length; i++) {
            hashes[i] = keccak256(abi.encode(customStructBArray[i].b));
        }
        return keccak256(abi.encode(hashes));
    }
}
```
