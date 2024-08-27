// SPDX-License-Identifier: MIT

pragma solidity >=0.7.0 <0.9.0;

import {GnosisSafeProxy} from "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxy.sol";
import {GnosisSafe} from "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract ProxyWalletFactory is Ownable {
    // The EIP-712 typehash for the contract's domain
    bytes32 public constant DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,uint256 chainId,address verifyingContract)"
        );

    // The EIP-712 typehash for the deposit id struct
    bytes32 public constant CREATE_PROXY_TYPEHASH =
        keccak256(
            "CreateProxy(address paymentToken,uint256 payment,address paymentReceiver,bytes32 salt)"
        );

    string public constant NAME = "Proxy Wallet Factory";

    address public masterCopy;

    address public fallbackHandler;
    mapping(address => bool) public managers;

    mapping(address => bool) public isDeployed;
    mapping(address => mapping(address => bool)) public isManagerDeployed;
    mapping(address => mapping(bytes32 => address)) public deployedProxyAddress;
    /* EIP712 */

    bytes32 public domainSeparator;

    /* STRUCTS */

    struct Sig {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /* EVENTS */
    event ProxyCreation(GnosisSafe proxy, address manager, bytes32 salt);
    event ManagerUpdated(address manager, bool status);

    /* CONSTRUCTOR */

    constructor(address _masterCopy, address _fallbackHandler) {
        masterCopy = _masterCopy;
        fallbackHandler = _fallbackHandler;

        domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(NAME)),
                _getChainIdInternal(),
                address(this)
            )
        );
    }

    function whitelistManager(address manager, bool status) external onlyOwner {
        managers[manager] = status;
        emit ManagerUpdated(manager, status);
    }

    function proxyCreationCode() public pure returns (bytes memory) {
        return type(GnosisSafeProxy).creationCode;
    }

    function getContractBytecode() public view returns (bytes memory) {
        return abi.encodePacked(proxyCreationCode(), abi.encode(masterCopy));
    }

    function getSalt(address user, bytes32 salt) public pure returns (bytes32) {
        return keccak256(abi.encode(user, salt));
    }

    function checkProxyWalletAddress(
        address _proxy,
        address _deployer
    ) public view returns (bool) {
        return managers[_deployer] && isManagerDeployed[_deployer][_proxy];
    }

    function computeProxyAddress(
        address user,
        bytes32 salt
    ) external view returns (address) {
        bytes32 uniqueSalt = getSalt(user, salt);
        bytes32 bytecodeHash = keccak256(getContractBytecode());
        bytes32 _data = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                uniqueSalt,
                bytecodeHash
            )
        );

        return address(uint160(uint256(_data)));
    }

    function createProxy(
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver,
        bytes32 salt,
        Sig calldata createSig
    ) external {
        address signer = _getSigner(
            paymentToken,
            payment,
            paymentReceiver,
            createSig
        );
        require(managers[signer], "ONLY_MANAGER");
        require(
            deployedProxyAddress[signer][salt] == address(0),
            "ALREADY_DEPLOYED"
        );
        GnosisSafe proxy;
        bytes memory deploymentData = getContractBytecode();
        bytes32 uniqueSalt = getSalt(signer, salt);
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            proxy := create2(
                0x0,
                add(0x20, deploymentData),
                mload(deploymentData),
                uniqueSalt
            )
        }
        require(address(proxy) != address(0), "create2 call failed");

        {
            address[] memory owners = new address[](1);
            owners[0] = signer;
            proxy.setup(
                owners,
                1,
                address(0),
                "",
                fallbackHandler,
                paymentToken,
                payment,
                paymentReceiver
            );
        }
        isDeployed[address(proxy)] = true;
        isManagerDeployed[signer][address(proxy)] = true;
        deployedProxyAddress[signer][salt] = address(proxy);
        emit ProxyCreation(proxy, signer, salt);
    }

    function createProxy(
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver,
        bytes32 salt
    ) external {
        address signer = msg.sender;
        require(managers[signer], "ONLY_MANAGER");
        require(
            deployedProxyAddress[signer][salt] == address(0),
            "ALREADY_DEPLOYED"
        );
        GnosisSafe proxy;
        bytes memory deploymentData = getContractBytecode();
        bytes32 uniqueSalt = getSalt(signer, salt);
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            proxy := create2(
                0x0,
                add(0x20, deploymentData),
                mload(deploymentData),
                uniqueSalt
            )
        }
        require(address(proxy) != address(0), "create2 call failed");

        {
            address[] memory owners = new address[](1);
            owners[0] = signer;
            proxy.setup(
                owners,
                1,
                address(0),
                "",
                fallbackHandler,
                paymentToken,
                payment,
                paymentReceiver
            );
        }
        isDeployed[address(proxy)] = true;
        isManagerDeployed[signer][address(proxy)] = true;
        deployedProxyAddress[signer][salt] = address(proxy);
        emit ProxyCreation(proxy, signer, salt);
    }

    function _getSigner(
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver,
        Sig calldata sig
    ) internal view returns (address) {
        bytes32 structHash = keccak256(
            abi.encode(
                CREATE_PROXY_TYPEHASH,
                paymentToken,
                payment,
                paymentReceiver
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        return ECDSA.recover(digest, sig.v, sig.r, sig.s);
    }

    function _getChainIdInternal() internal view returns (uint) {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        return chainId;
    }
}
