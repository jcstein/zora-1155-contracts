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
import {ZoraCreatorSignatureMinterStrategy} from "../../../src/minters/signature/ZoraCreatorSignatureMinterStrategy.sol";
import {IReadableAuthRegistry} from "../../../src/interfaces/IAuthRegistry.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MockAuthRegistry is IReadableAuthRegistry {
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
    ZoraCreatorSignatureMinterStrategy internal signatureMinter;
    address payable internal admin = payable(address(0x999));

    uint256 authorizedSignerPrivateKey = 0xA11CE;
    address payable internal authorizedSigner = payable(vm.addr(authorizedSignerPrivateKey));

    address payable internal fundsRecipient = payable(address(0x321));
    uint256 currentTime = 1000;

    IReadableAuthRegistry internal authRegistry;

    event SaleSet(address indexed mediaContract, ZoraCreatorSignatureMinterStrategy.SalesConfig salesConfig);
    event MintComment(address indexed sender, address indexed tokenContract, uint256 indexed tokenId, uint256 quantity, string comment);

    uint256 mintFeeAmount = 0.001 ether;
    address mintFeeRecipient;
    address factoryAddress;

    function setUp() external {
        bytes[] memory emptyData = new bytes[](0);
        mintFeeRecipient = vm.addr(1231231231);
        factoryAddress = address(0);
        ZoraCreator1155Impl targetImpl = new ZoraCreator1155Impl(mintFeeAmount, mintFeeRecipient, factoryAddress);
        Zora1155 proxy = new Zora1155(address(targetImpl));
        target = ZoraCreator1155Impl(address(proxy));
        target.initialize("test2", "test", ICreatorRoyaltiesControl.RoyaltyConfiguration(0, 0, address(0)), admin, emptyData);
        signatureMinter = new ZoraCreatorSignatureMinterStrategy();
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

        ZoraCreatorSignatureMinterStrategy.SalesConfig memory salesConfig = ZoraCreatorSignatureMinterStrategy.SalesConfig({
            authorizedSignatureCreators: authRegistry
        });

        emit SaleSet(address(target), salesConfig);

        target.callSale(newTokenId, signatureMinter, abi.encodeWithSelector(ZoraCreatorSignatureMinterStrategy.setSale.selector, salesConfig));
        vm.stopPrank();
    }

    function _setupTokenAndSignatureMinterWithAuthRegistry(uint256 maxSupply, IReadableAuthRegistry _authRegistry) private returns (uint256 newTokenId) {
        vm.startPrank(admin);
        newTokenId = target.setupNewToken("https://zora.co/testing/token.json", maxSupply);
        target.addPermission(newTokenId, address(signatureMinter), target.PERMISSION_BIT_MINTER());

        ZoraCreatorSignatureMinterStrategy.SalesConfig memory salesConfig = ZoraCreatorSignatureMinterStrategy.SalesConfig({
            authorizedSignatureCreators: _authRegistry
        });

        target.callSale(newTokenId, signatureMinter, abi.encodeWithSelector(ZoraCreatorSignatureMinterStrategy.setSale.selector, salesConfig));
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
        address mintTo,
        address _fundsRecipient
    ) private view returns (bytes memory) {
        bytes32 digest = signatureMinter.delegateCreateContractHashTypeData(
            _target,
            tokenId,
            nonce,
            quantity,
            pricePerToken,
            expiration,
            mintTo,
            _fundsRecipient
        );

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
        address fundsRecipient;
    }

    function _signMintRequestAndGetMintParams(
        SignMintAndRequestParam memory params
    ) private view returns (bytes memory minterArguments, uint256 mintValue, uint256 toSend) {
        // build signature:
        bytes memory signature = _signMintRequest(
            params.signer,
            params.target,
            params.tokenId,
            params.nonce,
            params.quantity,
            params.pricePerToken,
            params.expiration,
            params.mintTo,
            params.fundsRecipient
        );

        // build minter arguments, which are to be used for minting:
        minterArguments = signatureMinter.encodeMinterArguments(
            ZoraCreatorSignatureMinterStrategy.MintRequestCallData(
                params.nonce,
                params.pricePerToken,
                params.expiration,
                params.mintTo,
                params.fundsRecipient,
                signature
            )
        );

        // compute mint value:
        mintValue = params.pricePerToken * params.quantity;
        toSend = mintValue + params.quantity * mintFeeAmount;
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
        (bytes memory minterArguments, uint256 mintValue, uint256 toSend) = _signMintRequestAndGetMintParams(
            SignMintAndRequestParam(
                authorizedSignerPrivateKey,
                address(target),
                tokenId,
                randomBytes,
                quantity,
                pricePerToken,
                expiration,
                mintTo,
                fundsRecipient
            )
        );

        address executorAddress = vm.addr(12314324123);
        vm.deal(executorAddress, toSend);
        vm.prank(executorAddress);

        target.mint{value: toSend}(signatureMinter, tokenId, quantity, minterArguments);

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
            mintTo,
            fundsRecipient
        );

        // generate signature for hash using creators private key, and get mint arguments
        (bytes memory minterArguments, uint256 mintValue, uint256 toSend) = _signMintRequestAndGetMintParams(callParams);

        {
            vm.deal(executorAddress, toSend);
            vm.prank(executorAddress);

            target.mint{value: toSend}(signatureMinter, tokenId, quantity, minterArguments);
        }

        {
            // deal some more eth to the executor, and mint again, it should revert
            vm.deal(executorAddress, toSend);
            vm.prank(executorAddress);
            vm.expectRevert(ZoraCreatorSignatureMinterStrategy.AlreadyMinted.selector);
            target.mint{value: toSend}(signatureMinter, tokenId, quantity, minterArguments);
        }

        {
            // now generate a new signature with a diff random bytes value
            callParams.nonce = _flipBytes(randomBytes);
            // create the signature from an authorized signer:
            (minterArguments, mintValue, toSend) = _signMintRequestAndGetMintParams(callParams);

            // mint with these new args, should succeed
            vm.prank(executorAddress);
            target.mint{value: toSend}(signatureMinter, tokenId, quantity, minterArguments);
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
            signature = _signMintRequest(privateKeyToUse, address(target), tokenId, randomBytes, quantity, pricePerToken, expiration, mintTo, fundsRecipient);
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

        uint256 toSend = mintValue + mintFeeAmount * quantity;

        // now build the calldata
        bytes memory minterArguments = signatureMinter.encodeMinterArguments(
            ZoraCreatorSignatureMinterStrategy.MintRequestCallData(randomBytes, pricePerToken, expiration, mintTo, fundsRecipient, signature)
        );

        address executorAddress = vm.addr(12314324123);
        vm.deal(executorAddress, toSend);
        vm.prank(executorAddress);

        // should revert with invalid signature
        vm.expectRevert(ZoraCreatorSignatureMinterStrategy.InvalidSignature.selector);
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
            mintTo,
            fundsRecipient
        );

        (bytes memory minterArguments, , uint256 toSend) = _signMintRequestAndGetMintParams(callParams);

        // alter time to be past expiration
        vm.warp(expiration + timeSinceExpired);

        address executorAddress = vm.addr(12314324123);
        vm.deal(executorAddress, toSend);
        vm.prank(executorAddress);

        // should revert with expired
        vm.expectRevert(abi.encodeWithSelector(ZoraCreatorSignatureMinterStrategy.Expired.selector, expiration));
        target.mint{value: toSend}(signatureMinter, tokenId, quantity, minterArguments);
    }

    function test_mint_revertsWhen_wrongValueSent(uint128 pricePerToken, uint64 quantity) external {
        vm.assume(pricePerToken > 0 && pricePerToken < 1 ether && quantity > 0 && quantity < 1000);
        uint256 wrongAmountToSend = pricePerToken * quantity + 1 ether;
        uint64 maxSupply = quantity + 1;

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
            mintTo,
            fundsRecipient
        );

        (bytes memory minterArguments, , ) = _signMintRequestAndGetMintParams(callParams);

        address executorAddress = vm.addr(12314324123);
        uint256 mintFee = quantity * mintFeeAmount;
        vm.deal(executorAddress, wrongAmountToSend + mintFee);
        vm.prank(executorAddress);

        vm.expectRevert(abi.encodeWithSelector(ZoraCreatorSignatureMinterStrategy.WrongValueSent.selector, pricePerToken * quantity, wrongAmountToSend));
        target.mint{value: wrongAmountToSend + mintFee}(signatureMinter, tokenId, quantity, minterArguments);
    }

    function test_mint_fundsRecipientRecievesFunds(uint64 pricePerToken, uint64 quantity, uint64 maxSupply) external {
        vm.assume(pricePerToken > 0);
        vm.assume(quantity > 0);
        vm.assume(maxSupply >= quantity);
        address mintTo = vm.addr(12312312);
        uint256 tokenId = _setupTokenAndSignatureMinter(maxSupply);
        bytes32 randomBytes = bytes32(uint256(123123));
        uint256 expiration = currentTime + 5;

        // generate signature for data using creators private key
        (bytes memory minterArguments, uint256 mintValue, uint256 toSend) = _signMintRequestAndGetMintParams(
            SignMintAndRequestParam(
                authorizedSignerPrivateKey,
                address(target),
                tokenId,
                randomBytes,
                quantity,
                pricePerToken,
                expiration,
                mintTo,
                fundsRecipient
            )
        );

        uint256 beforeFundsRecipientBalance = fundsRecipient.balance;

        address executorAddress = vm.addr(12314324123);
        vm.deal(executorAddress, toSend);
        vm.prank(executorAddress);

        target.mint{value: toSend}(signatureMinter, tokenId, quantity, minterArguments);

        assertEq(fundsRecipient.balance - beforeFundsRecipientBalance, mintValue);
    }

    function test_mint_revertsWhen_mintValueButNoFundsRecipient(uint64 pricePerToken, uint64 quantity, uint64 maxSupply) external {
        vm.assume(pricePerToken > 0);
        vm.assume(quantity > 0);
        vm.assume(maxSupply >= quantity);
        address mintTo = vm.addr(12312312);
        uint256 tokenId = _setupTokenAndSignatureMinter(maxSupply);
        bytes32 randomBytes = bytes32(uint256(123123));
        uint256 expiration = currentTime + 5;

        // generate signature for data using creators private key
        (bytes memory minterArguments, , uint256 toSend) = _signMintRequestAndGetMintParams(
            SignMintAndRequestParam(
                authorizedSignerPrivateKey,
                address(target),
                tokenId,
                randomBytes,
                quantity,
                pricePerToken,
                expiration,
                mintTo,
                payable(address(0))
            )
        );

        address executorAddress = vm.addr(12314324123);
        vm.deal(executorAddress, toSend);
        vm.prank(executorAddress);

        vm.expectRevert(ZoraCreatorSignatureMinterStrategy.MissingFundsRecipient.selector);
        target.mint{value: toSend}(signatureMinter, tokenId, quantity, minterArguments);
    }
}
