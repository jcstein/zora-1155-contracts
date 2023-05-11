// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "forge-std/Test.sol";
import {ZoraCreator1155Impl} from "../../../src/nft/ZoraCreator1155Impl.sol";
import {Zora1155} from "../../../src/proxies/Zora1155.sol";
import {IZoraCreator1155} from "../../../src/interfaces/IZoraCreator1155.sol";
import {IMinter1155} from "../../../src/interfaces/IMinter1155.sol";
import {ICreatorRoyaltiesControl} from "../../../src/interfaces/ICreatorRoyaltiesControl.sol";
import {IZoraCreator1155Factory} from "../../../src/interfaces/IZoraCreator1155Factory.sol";
import {ILimitedMintPerAddress} from "../../../src/interfaces/ILimitedMintPerAddress.sol";
import {ZoraSignatureMinterStrategy, IAuthRegistry} from "../../../src/minters/signature/ZoraSignatureMinterStrategy.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MockAuthRegistry is IAuthRegistry {
    mapping(address => bool) public auth;

    constructor() {}

    function addAuthorized(address _address) external {
        auth[_address] = true;
    }

    function isAuthorized(address _address) external view override returns (bool) {
        return auth[_address];
    }
}

contract ZoraSignatureMinterStategyTest is Test {
    ZoraCreator1155Impl internal target;
    ZoraSignatureMinterStrategy internal signatureMinter;
    address payable internal admin = payable(address(0x999));

    uint256 authorizedSignerPrivateKey = 0xA11CE;
    address payable internal authorizedSigner = payable(vm.addr(authorizedSignerPrivateKey));

    address payable internal fundsRecipient = payable(address(0x321));
    uint256 currentTime = 1000;

    IAuthRegistry internal authRegistry;

    event SaleSet(address indexed mediaContract, ZoraSignatureMinterStrategy.SalesConfig salesConfig);
    event MintComment(address indexed sender, address indexed tokenContract, uint256 indexed tokenId, uint256 quantity, string comment);

    function setUp() external {
        bytes[] memory emptyData = new bytes[](0);
        ZoraCreator1155Impl targetImpl = new ZoraCreator1155Impl(0, address(0), address(0));
        Zora1155 proxy = new Zora1155(address(targetImpl));
        target = ZoraCreator1155Impl(address(proxy));
        target.initialize("test2", "test", ICreatorRoyaltiesControl.RoyaltyConfiguration(0, 0, address(0)), admin, emptyData);
        signatureMinter = new ZoraSignatureMinterStrategy();
        authRegistry = new MockAuthRegistry();
        MockAuthRegistry(address(authRegistry)).addAuthorized(authorizedSigner);
        // set the time to be the current time
        vm.warp(currentTime);
    }

    function test_ContractName() external {
        assertEq(signatureMinter.contractName(), "Signature Sale Strategy");
    }

    function test_Version() external {
        assertEq(signatureMinter.contractVersion(), "1.0.0");
    }

    function test_setSalesConfig_emitsEvent() external {
        vm.startPrank(admin);
        uint256 newTokenId = target.setupNewToken("https://zora.co/testing/token.json", 10);
        target.addPermission(newTokenId, address(signatureMinter), target.PERMISSION_BIT_MINTER());
        vm.expectEmit(true, true, true, true);

        ZoraSignatureMinterStrategy.SalesConfig memory salesConfig = ZoraSignatureMinterStrategy.SalesConfig({
            authorizedSignatureCreators: authRegistry,
            fundsRecipient: fundsRecipient
        });

        emit SaleSet(address(target), salesConfig);

        target.callSale(newTokenId, signatureMinter, abi.encodeWithSelector(ZoraSignatureMinterStrategy.setSale.selector, salesConfig));
        vm.stopPrank();
    }

    function _setupTokenAndSignatureMinterWithAuthRegistry(uint256 maxSupply, IAuthRegistry _authRegistry) private returns (uint256 newTokenId) {
        vm.startPrank(admin);
        newTokenId = target.setupNewToken("https://zora.co/testing/token.json", maxSupply);
        target.addPermission(newTokenId, address(signatureMinter), target.PERMISSION_BIT_MINTER());

        ZoraSignatureMinterStrategy.SalesConfig memory salesConfig = ZoraSignatureMinterStrategy.SalesConfig({
            authorizedSignatureCreators: _authRegistry,
            fundsRecipient: fundsRecipient
        });

        target.callSale(newTokenId, signatureMinter, abi.encodeWithSelector(ZoraSignatureMinterStrategy.setSale.selector, salesConfig));
        vm.stopPrank();
    }

    function _setupTokenAndSignatureMinter(uint256 maxSupply) private returns (uint256 newTokenId) {
        return _setupTokenAndSignatureMinterWithAuthRegistry(maxSupply, authRegistry);
    }

    function _sign(uint256 privateKey, bytes32 digest) private pure returns (bytes memory) {
        // sign the message
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        // combine into a single bytes array
        return abi.encodePacked(r, s, v);
    }

    function _signMintRequest(
        uint256 signer,
        address _target,
        uint256 tokenId,
        bytes32 nonce,
        uint256 quantity,
        uint256 pricePerToken,
        uint256 expiration,
        address mintTo
    ) private view returns (bytes memory) {
        bytes32 digest = signatureMinter.delegateCreateContractHashTypeData(_target, tokenId, nonce, quantity, pricePerToken, expiration, mintTo);

        // generate signature for hash using creators private key
        return _sign(signer, digest);
    }

    struct SignMintAndRequestParam {
        uint256 signer;
        address target;
        uint256 tokenId;
        bytes32 nonce;
        uint256 quantity;
        uint256 pricePerToken;
        uint256 expiration;
        address mintTo;
    }

    function _signMintRequestAndGetMintParams(SignMintAndRequestParam memory params) private view returns (bytes memory minterArguments, uint256 mintValue) {
        // build signature:
        bytes memory signature = _signMintRequest(
            params.signer,
            params.target,
            params.tokenId,
            params.nonce,
            params.quantity,
            params.pricePerToken,
            params.expiration,
            params.mintTo
        );

        // build minter arguments, which are to be used for minting:
        minterArguments = signatureMinter.encodeMinterArgumets(params.nonce, params.pricePerToken, params.expiration, params.mintTo, signature);

        // compute mint value:
        mintValue = params.pricePerToken * params.quantity;
    }

    function _flipBytes(bytes32 toFlip) private pure returns (bytes32) {
        bytes32 mask = 0x0000000000000000000000000000000000000000000000000000000000000001; // mask with the LSB flipped
        return toFlip ^ mask; // XOR the original with the mask to flip the LSB
    }

    function test_mint_succeedsWhen_ValidSignature(
        uint64 pricePerToken,
        uint64 quantity,
        uint64 maxSupply,
        uint64 expirationInFuture,
        bytes32 randomBytes
    ) external {
        vm.assume(quantity > 0);
        vm.assume(maxSupply >= quantity);
        vm.assume(expirationInFuture > 0);
        address mintTo = vm.addr(12312312);
        uint256 tokenId = _setupTokenAndSignatureMinter(maxSupply);

        uint256 expiration = currentTime + expirationInFuture;

        // generate signature for data using creators private key
        (bytes memory minterArguments, uint256 mintValue) = _signMintRequestAndGetMintParams(
            SignMintAndRequestParam(authorizedSignerPrivateKey, address(target), tokenId, randomBytes, quantity, pricePerToken, expiration, mintTo)
        );

        address executorAddress = vm.addr(12314324123);
        vm.deal(executorAddress, mintValue);
        vm.prank(executorAddress);

        target.mint{value: mintValue}(signatureMinter, tokenId, quantity, minterArguments);

        // validate that the mintTo address has a balance of quantity for the token
        assertEq(target.balanceOf(mintTo, tokenId), quantity);
    }

    function test_mint_revertsWhen_mintedTwice_butSucceedsWhen_randomBytesChanges(
        uint256 pricePerToken,
        uint256 quantity,
        uint256 maxSupply,
        uint256 expirationInFuture,
        bytes32 randomBytes
    ) external {
        {
            vm.assume(pricePerToken < 5 ether);
            vm.assume(quantity < 100000);
            vm.assume(quantity > 0);
            // since we will mint twicek
            vm.assume(maxSupply >= uint256(quantity) * 2);
            vm.assume(expirationInFuture > 0 && expirationInFuture < 3 days);
        }
        address mintTo = vm.addr(12312312);
        uint256 tokenId = _setupTokenAndSignatureMinter(maxSupply);

        uint256 expiration = currentTime + expirationInFuture;

        address executorAddress = vm.addr(12314324123);

        SignMintAndRequestParam memory callParams = SignMintAndRequestParam(
            authorizedSignerPrivateKey,
            address(target),
            tokenId,
            randomBytes,
            quantity,
            pricePerToken,
            expiration,
            mintTo
        );

        // generate signature for hash using creators private key, and get mint arguments
        (bytes memory minterArguments, uint256 mintValue) = _signMintRequestAndGetMintParams(callParams);

        {
            vm.deal(executorAddress, mintValue);
            vm.prank(executorAddress);

            target.mint{value: mintValue}(signatureMinter, tokenId, quantity, minterArguments);
        }

        {
            // deal some more eth to the executor, and mint again, it should revert
            vm.deal(executorAddress, mintValue);
            vm.prank(executorAddress);
            vm.expectRevert(ZoraSignatureMinterStrategy.AlreadyMinted.selector);
            target.mint{value: mintValue}(signatureMinter, tokenId, quantity, minterArguments);
        }

        {
            // now generate a new signature with a diff random bytes value
            callParams.nonce = _flipBytes(randomBytes);
            // create the signature from an authorized signer:
            (minterArguments, mintValue) = _signMintRequestAndGetMintParams(callParams);

            // mint with these new args, should succeed
            vm.prank(executorAddress);
            target.mint{value: mintValue}(signatureMinter, tokenId, quantity, minterArguments);
        }

        // it should have minted twice
        assertEq(target.balanceOf(mintTo, tokenId), quantity * 2);
    }

    function test_mint_revertsWhen_invalidSignature(
        bool nonAuthorizedSigner,
        bool tokenIdWrong,
        bool pricePerTokenWrong,
        bool quantityWrong,
        bool experitionWrong,
        bool mintToWrong,
        bool randomBytesWrong
    ) external {
        vm.assume(nonAuthorizedSigner || tokenIdWrong || quantityWrong || experitionWrong || mintToWrong || randomBytesWrong);
        uint256 pricePerToken = 2 ether;
        uint64 quantity = 4;
        uint64 maxSupply = 10;

        bytes32 randomBytes = bytes32(uint256(123123));
        address mintTo = vm.addr(123123123);

        uint256 expiration = currentTime + 2 days;

        uint256 tokenId = _setupTokenAndSignatureMinter(maxSupply);

        // if non authorized signer, change private key to use to another private key thats not authorized
        uint256 privateKeyToUse = nonAuthorizedSigner ? 0xA11CD : authorizedSignerPrivateKey;

        bytes memory signature;

        {
            // create the signature from an authorized signer with the original correct data
            signature = _signMintRequest(privateKeyToUse, address(target), tokenId, randomBytes, quantity, pricePerToken, expiration, mintTo);
        }

        // store the mint value before affecting price per token below
        uint256 mintValue = uint256(pricePerToken) * quantity;

        {
            // now start messing with the data
            if (tokenIdWrong) {
                tokenId = _setupTokenAndSignatureMinter(maxSupply);
            }
            if (quantityWrong) {
                quantity = quantity + 1;
            }
            if (experitionWrong) {
                expiration = expiration + 1;
            }
            if (mintToWrong) {
                mintTo = vm.addr(123);
            }
            if (randomBytesWrong) {
                // randomly alter bytes (by flipping them)
                randomBytes = _flipBytes(randomBytes);
            }
            if (pricePerTokenWrong) {
                pricePerToken = pricePerToken + 1;
            }
        }

        // now build the calldata
        bytes memory minterArguments = abi.encode(randomBytes, pricePerToken, expiration, mintTo, signature);

        address executorAddress = vm.addr(12314324123);
        vm.deal(executorAddress, mintValue);
        vm.prank(executorAddress);

        // should revert with invalid signature
        vm.expectRevert(ZoraSignatureMinterStrategy.InvalidSignature.selector);
        target.mint{value: mintValue}(signatureMinter, tokenId, quantity, minterArguments);
    }

    function test_mint_revertsWhen_expired(uint128 expirationInFuture, uint8 timeSinceExpired) external {
        uint256 pricePerToken = 2 ether;
        vm.assume(expirationInFuture > 0);
        vm.assume(timeSinceExpired > 0);
        uint64 quantity = 4;
        uint64 maxSupply = 10;

        bytes32 randomBytes = bytes32(uint256(123123));
        address mintTo = vm.addr(123123123);

        uint256 expiration = currentTime + expirationInFuture;

        uint256 tokenId = _setupTokenAndSignatureMinter(maxSupply);

        SignMintAndRequestParam memory callParams = SignMintAndRequestParam(
            authorizedSignerPrivateKey,
            address(target),
            tokenId,
            randomBytes,
            quantity,
            pricePerToken,
            expiration,
            mintTo
        );

        (bytes memory minterArguments, uint256 mintValue) = _signMintRequestAndGetMintParams(callParams);

        // alter time to be past expiration
        vm.warp(expiration + timeSinceExpired);

        address executorAddress = vm.addr(12314324123);
        vm.deal(executorAddress, mintValue);
        vm.prank(executorAddress);

        // should revert with expired
        vm.expectRevert(abi.encodeWithSelector(ZoraSignatureMinterStrategy.Expired.selector, expiration));
        target.mint{value: mintValue}(signatureMinter, tokenId, quantity, minterArguments);
    }

    function test_mint_revertsWhen_wrongValueSent(uint128 pricePerToken, int8 valueDifference) external {
        vm.assume(valueDifference != 0);
        uint64 quantity = 4;
        uint64 maxSupply = 10;

        bytes32 randomBytes = bytes32(uint256(123123));
        address mintTo = vm.addr(123123123);

        uint256 expiration = currentTime + 2 days;

        uint256 tokenId = _setupTokenAndSignatureMinter(maxSupply);

        SignMintAndRequestParam memory callParams = SignMintAndRequestParam(
            authorizedSignerPrivateKey,
            address(target),
            tokenId,
            randomBytes,
            quantity,
            pricePerToken,
            expiration,
            mintTo
        );

        (bytes memory minterArguments, uint256 mintValue) = _signMintRequestAndGetMintParams(callParams);

        // alter value to send
        uint256 toSend = uint256(int256(mintValue) + valueDifference);

        address executorAddress = vm.addr(12314324123);
        vm.deal(executorAddress, toSend);
        vm.prank(executorAddress);

        // should revert
        vm.expectRevert(abi.encodeWithSelector(ZoraSignatureMinterStrategy.WrongValueSent.selector, mintValue, toSend));
        target.mint{value: toSend}(signatureMinter, tokenId, quantity, minterArguments);
    }
}
