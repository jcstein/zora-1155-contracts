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

    event SaleSet(address indexed mediaContract, uint256 indexed tokenId, ZoraSignatureMinterStrategy.SalesConfig salesConfig);
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

        emit SaleSet(address(target), newTokenId, salesConfig);

        target.callSale(newTokenId, signatureMinter, abi.encodeWithSelector(ZoraSignatureMinterStrategy.setSale.selector, newTokenId, salesConfig));
        vm.stopPrank();
    }

    function _setupTokenAndSignatureMinter(uint256 maxSupply) private returns (uint256 newTokenId) {
        vm.startPrank(admin);
        newTokenId = target.setupNewToken("https://zora.co/testing/token.json", maxSupply);
        target.addPermission(newTokenId, address(signatureMinter), target.PERMISSION_BIT_MINTER());

        ZoraSignatureMinterStrategy.SalesConfig memory salesConfig = ZoraSignatureMinterStrategy.SalesConfig({
            authorizedSignatureCreators: authRegistry,
            fundsRecipient: fundsRecipient
        });

        target.callSale(newTokenId, signatureMinter, abi.encodeWithSelector(ZoraSignatureMinterStrategy.setSale.selector, newTokenId, salesConfig));
        vm.stopPrank();
    }

    function _sign(uint256 privateKey, bytes32 digest) private pure returns (bytes memory) {
        // sign the message
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        // combine into a single bytes array
        return abi.encodePacked(r, s, v);
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

        // create the signature from an authorized signer:
        bytes32 digest = signatureMinter.delegateCreateContractHashTypeData(address(target), tokenId, randomBytes, quantity, pricePerToken, expiration, mintTo);

        // generate signature for hash using creators private key
        bytes memory signature = _sign(authorizedSignerPrivateKey, digest);

        // now build the calldata
        bytes memory minterArguments = abi.encode(randomBytes, pricePerToken, expiration, mintTo, signature);

        // now execute the mint as anyone (doesn't need to be the mintTo address)
        uint256 mintValue = uint256(pricePerToken) * quantity;
        address executorAddress = vm.addr(12314324123);
        vm.deal(executorAddress, mintValue);
        vm.prank(executorAddress);

        target.mint{value: mintValue}(signatureMinter, tokenId, quantity, minterArguments);

        // validate that the mintTo address has a balance of quantity for the token
        assertEq(target.balanceOf(mintTo, tokenId), quantity);
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

        // create the signature from an authorized signer with the original correct data
        bytes32 digest = signatureMinter.delegateCreateContractHashTypeData(address(target), tokenId, randomBytes, quantity, pricePerToken, expiration, mintTo);

        // if non authorized signer, change private key to use to another private key thats not authorized
        uint256 privateKeyToUse = nonAuthorizedSigner ? 0xA11CD : authorizedSignerPrivateKey;

        // generate signature for hash using private key - which could be from a non-autohrized signer
        bytes memory signature = _sign(privateKeyToUse, digest);

        // store the mint value before affecting price per token below
        uint256 mintValue = uint256(pricePerToken) * quantity;

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
            bytes32 mask = 0x0000000000000000000000000000000000000000000000000000000000000001; // mask with the LSB flipped
            randomBytes = randomBytes ^ mask; // XOR the original with the mask to flip the LSB
        }
        if (pricePerTokenWrong) {
            pricePerToken = pricePerToken + 1;
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

    // function test_MintWithCommentBackwardsCompatible() external {
    //     vm.startPrank(admin);
    //     uint256 newTokenId = target.setupNewToken("https://zora.co/testing/token.json", 10);
    //     target.addPermission(newTokenId, address(signatureMinter), target.PERMISSION_BIT_MINTER());
    //     vm.expectEmit(true, true, true, true);
    //     emit SaleSet(
    //         address(target),
    //         newTokenId,
    //         ZoraCreatorFixedPriceSaleStrategy.SalesConfig({
    //             pricePerToken: 1 ether,
    //             saleStart: 0,
    //             saleEnd: type(uint64).max,
    //             maxTokensPerAddress: 0,
    //             fundsRecipient: address(0)
    //         })
    //     );
    //     target.callSale(
    //         newTokenId,
    //         signatureMinter,
    //         abi.encodeWithSelector(
    //             ZoraCreatorFixedPriceSaleStrategy.setSale.selector,
    //             newTokenId,
    //             ZoraCreatorFixedPriceSaleStrategy.SalesConfig({
    //                 pricePerToken: 1 ether,
    //                 saleStart: 0,
    //                 saleEnd: type(uint64).max,
    //                 maxTokensPerAddress: 0,
    //                 fundsRecipient: address(0)
    //             })
    //         )
    //     );
    //     vm.stopPrank();

    //     address tokenRecipient = address(322);
    //     vm.deal(tokenRecipient, 20 ether);

    //     vm.startPrank(tokenRecipient);
    //     target.mint{value: 10 ether}(signatureMinter, newTokenId, 10, abi.encode(tokenRecipient));

    //     assertEq(target.balanceOf(tokenRecipient, newTokenId), 10);
    //     assertEq(address(target).balance, 10 ether);

    //     vm.stopPrank();
    // }

    // function test_MintWithComment() external {
    //     vm.startPrank(admin);
    //     uint256 newTokenId = target.setupNewToken("https://zora.co/testing/token.json", 10);
    //     target.addPermission(newTokenId, address(signatureMinter), target.PERMISSION_BIT_MINTER());
    //     vm.expectEmit(true, true, true, true);
    //     emit SaleSet(
    //         address(target),
    //         newTokenId,
    //         ZoraCreatorFixedPriceSaleStrategy.SalesConfig({
    //             pricePerToken: 1 ether,
    //             saleStart: 0,
    //             saleEnd: type(uint64).max,
    //             maxTokensPerAddress: 0,
    //             fundsRecipient: address(0)
    //         })
    //     );
    //     target.callSale(
    //         newTokenId,
    //         signatureMinter,
    //         abi.encodeWithSelector(
    //             ZoraCreatorFixedPriceSaleStrategy.setSale.selector,
    //             newTokenId,
    //             ZoraCreatorFixedPriceSaleStrategy.SalesConfig({
    //                 pricePerToken: 1 ether,
    //                 saleStart: 0,
    //                 saleEnd: type(uint64).max,
    //                 maxTokensPerAddress: 0,
    //                 fundsRecipient: address(0)
    //             })
    //         )
    //     );
    //     vm.stopPrank();

    //     address tokenRecipient = address(322);
    //     vm.deal(tokenRecipient, 20 ether);

    //     vm.startPrank(tokenRecipient);
    //     vm.expectEmit(true, true, true, true);
    //     emit MintComment(tokenRecipient, address(target), newTokenId, 10, "test comment");
    //     target.mint{value: 10 ether}(signatureMinter, newTokenId, 10, abi.encode(tokenRecipient, "test comment"));

    //     assertEq(target.balanceOf(tokenRecipient, newTokenId), 10);
    //     assertEq(address(target).balance, 10 ether);

    //     vm.stopPrank();
    // }

    // function test_SaleStart() external {
    //     vm.startPrank(admin);
    //     uint256 newTokenId = target.setupNewToken("https://zora.co/testing/token.json", 10);
    //     target.addPermission(newTokenId, address(signatureMinter), target.PERMISSION_BIT_MINTER());
    //     target.callSale(
    //         newTokenId,
    //         signatureMinter,
    //         abi.encodeWithSelector(
    //             ZoraCreatorFixedPriceSaleStrategy.setSale.selector,
    //             newTokenId,
    //             ZoraCreatorFixedPriceSaleStrategy.SalesConfig({
    //                 pricePerToken: 1 ether,
    //                 saleStart: uint64(block.timestamp + 1 days),
    //                 saleEnd: type(uint64).max,
    //                 maxTokensPerAddress: 10,
    //                 fundsRecipient: address(0)
    //             })
    //         )
    //     );
    //     vm.stopPrank();

    //     address tokenRecipient = address(322);
    //     vm.deal(tokenRecipient, 20 ether);

    //     vm.expectRevert(abi.encodeWithSignature("SaleHasNotStarted()"));
    //     vm.prank(tokenRecipient);
    //     target.mint{value: 10 ether}(signatureMinter, newTokenId, 10, abi.encode(tokenRecipient, ""));
    // }

    // function test_SaleEnd() external {
    //     vm.warp(2 days);

    //     vm.startPrank(admin);
    //     uint256 newTokenId = target.setupNewToken("https://zora.co/testing/token.json", 10);
    //     target.addPermission(newTokenId, address(signatureMinter), target.PERMISSION_BIT_MINTER());
    //     target.callSale(
    //         newTokenId,
    //         signatureMinter,
    //         abi.encodeWithSelector(
    //             ZoraCreatorFixedPriceSaleStrategy.setSale.selector,
    //             newTokenId,
    //             ZoraCreatorFixedPriceSaleStrategy.SalesConfig({
    //                 pricePerToken: 1 ether,
    //                 saleStart: 0,
    //                 saleEnd: uint64(1 days),
    //                 maxTokensPerAddress: 0,
    //                 fundsRecipient: address(0)
    //             })
    //         )
    //     );
    //     vm.stopPrank();

    //     address tokenRecipient = address(322);
    //     vm.deal(tokenRecipient, 20 ether);

    //     vm.expectRevert(abi.encodeWithSignature("SaleEnded()"));
    //     vm.prank(tokenRecipient);
    //     target.mint{value: 10 ether}(signatureMinter, newTokenId, 10, abi.encode(tokenRecipient, ""));
    // }

    // function test_MaxTokensPerAddress() external {
    //     vm.warp(2 days);

    //     vm.startPrank(admin);
    //     uint256 newTokenId = target.setupNewToken("https://zora.co/testing/token.json", 10);
    //     target.addPermission(newTokenId, address(signatureMinter), target.PERMISSION_BIT_MINTER());
    //     target.callSale(
    //         newTokenId,
    //         signatureMinter,
    //         abi.encodeWithSelector(
    //             ZoraCreatorFixedPriceSaleStrategy.setSale.selector,
    //             newTokenId,
    //             ZoraCreatorFixedPriceSaleStrategy.SalesConfig({
    //                 pricePerToken: 1 ether,
    //                 saleStart: 0,
    //                 saleEnd: type(uint64).max,
    //                 maxTokensPerAddress: 5,
    //                 fundsRecipient: address(0)
    //             })
    //         )
    //     );
    //     vm.stopPrank();

    //     address tokenRecipient = address(322);
    //     vm.deal(tokenRecipient, 20 ether);

    //     vm.prank(tokenRecipient);
    //     vm.expectRevert(abi.encodeWithSelector(ILimitedMintPerAddress.UserExceedsMintLimit.selector, tokenRecipient, 5, 6));
    //     target.mint{value: 6 ether}(signatureMinter, newTokenId, 6, abi.encode(tokenRecipient, ""));
    // }

    // function testFail_setupMint() external {
    //     vm.startPrank(admin);
    //     uint256 newTokenId = target.setupNewToken("https://zora.co/testing/token.json", 10);
    //     target.addPermission(newTokenId, address(signatureMinter), target.PERMISSION_BIT_MINTER());
    //     target.callSale(
    //         newTokenId,
    //         signatureMinter,
    //         abi.encodeWithSelector(
    //             ZoraCreatorFixedPriceSaleStrategy.setSale.selector,
    //             newTokenId,
    //             ZoraCreatorFixedPriceSaleStrategy.SalesConfig({
    //                 pricePerToken: 1 ether,
    //                 saleStart: 0,
    //                 saleEnd: type(uint64).max,
    //                 maxTokensPerAddress: 9,
    //                 fundsRecipient: address(0)
    //             })
    //         )
    //     );
    //     vm.stopPrank();

    //     address tokenRecipient = address(322);
    //     vm.deal(tokenRecipient, 20 ether);

    //     vm.startPrank(tokenRecipient);
    //     target.mint{value: 10 ether}(signatureMinter, newTokenId, 10, abi.encode(tokenRecipient));

    //     assertEq(target.balanceOf(tokenRecipient, newTokenId), 10);
    //     assertEq(address(target).balance, 10 ether);

    //     vm.stopPrank();
    // }

    // function test_PricePerToken() external {
    //     vm.warp(2 days);

    //     vm.startPrank(admin);
    //     uint256 newTokenId = target.setupNewToken("https://zora.co/testing/token.json", 10);
    //     target.addPermission(newTokenId, address(signatureMinter), target.PERMISSION_BIT_MINTER());
    //     target.callSale(
    //         newTokenId,
    //         signatureMinter,
    //         abi.encodeWithSelector(
    //             ZoraCreatorFixedPriceSaleStrategy.setSale.selector,
    //             newTokenId,
    //             ZoraCreatorFixedPriceSaleStrategy.SalesConfig({
    //                 pricePerToken: 1 ether,
    //                 saleStart: 0,
    //                 saleEnd: type(uint64).max,
    //                 maxTokensPerAddress: 0,
    //                 fundsRecipient: address(0)
    //             })
    //         )
    //     );
    //     vm.stopPrank();

    //     address tokenRecipient = address(322);
    //     vm.deal(tokenRecipient, 20 ether);

    //     vm.startPrank(tokenRecipient);
    //     vm.expectRevert(abi.encodeWithSignature("WrongValueSent()"));
    //     target.mint{value: 0.9 ether}(signatureMinter, newTokenId, 1, abi.encode(tokenRecipient, ""));
    //     vm.expectRevert(abi.encodeWithSignature("WrongValueSent()"));
    //     target.mint{value: 1.1 ether}(signatureMinter, newTokenId, 1, abi.encode(tokenRecipient, ""));
    //     target.mint{value: 1 ether}(signatureMinter, newTokenId, 1, abi.encode(tokenRecipient, ""));
    //     vm.stopPrank();
    // }

    // function test_FundsRecipient() external {
    //     vm.startPrank(admin);
    //     uint256 newTokenId = target.setupNewToken("https://zora.co/testing/token.json", 10);
    //     target.addPermission(newTokenId, address(signatureMinter), target.PERMISSION_BIT_MINTER());
    //     target.callSale(
    //         newTokenId,
    //         signatureMinter,
    //         abi.encodeWithSelector(
    //             ZoraCreatorFixedPriceSaleStrategy.setSale.selector,
    //             newTokenId,
    //             ZoraCreatorFixedPriceSaleStrategy.SalesConfig({
    //                 pricePerToken: 1 ether,
    //                 saleStart: 0,
    //                 saleEnd: type(uint64).max,
    //                 maxTokensPerAddress: 0,
    //                 fundsRecipient: address(1)
    //             })
    //         )
    //     );
    //     vm.stopPrank();

    //     address tokenRecipient = address(322);
    //     vm.deal(tokenRecipient, 20 ether);
    //     vm.prank(tokenRecipient);
    //     target.mint{value: 10 ether}(signatureMinter, newTokenId, 10, abi.encode(tokenRecipient, ""));

    //     assertEq(address(1).balance, 10 ether);
    // }

    // function test_MintedPerRecipientGetter() external {
    //     vm.startPrank(admin);
    //     uint256 newTokenId = target.setupNewToken("https://zora.co/testing/token.json", 10);
    //     target.addPermission(newTokenId, address(signatureMinter), target.PERMISSION_BIT_MINTER());
    //     target.callSale(
    //         newTokenId,
    //         signatureMinter,
    //         abi.encodeWithSelector(
    //             ZoraCreatorFixedPriceSaleStrategy.setSale.selector,
    //             newTokenId,
    //             ZoraCreatorFixedPriceSaleStrategy.SalesConfig({
    //                 pricePerToken: 0 ether,
    //                 saleStart: 0,
    //                 saleEnd: type(uint64).max,
    //                 maxTokensPerAddress: 20,
    //                 fundsRecipient: address(0)
    //             })
    //         )
    //     );
    //     vm.stopPrank();

    //     address tokenRecipient = address(322);
    //     vm.deal(tokenRecipient, 20 ether);
    //     vm.prank(tokenRecipient);
    //     target.mint{value: 0 ether}(signatureMinter, newTokenId, 10, abi.encode(tokenRecipient, ""));

    //     assertEq(signatureMinter.getMintedPerWallet(address(target), newTokenId, tokenRecipient), 10);
    // }

    // function test_ResetSale() external {
    //     vm.startPrank(admin);
    //     uint256 newTokenId = target.setupNewToken("https://zora.co/testing/token.json", 10);
    //     target.addPermission(newTokenId, address(signatureMinter), target.PERMISSION_BIT_MINTER());
    //     vm.expectEmit(false, false, false, false);
    //     emit SaleSet(
    //         address(target),
    //         newTokenId,
    //         ZoraCreatorFixedPriceSaleStrategy.SalesConfig({pricePerToken: 0, saleStart: 0, saleEnd: 0, maxTokensPerAddress: 0, fundsRecipient: address(0)})
    //     );
    //     target.callSale(newTokenId, signatureMinter, abi.encodeWithSelector(ZoraCreatorFixedPriceSaleStrategy.resetSale.selector, newTokenId));
    //     vm.stopPrank();

    //     ZoraCreatorFixedPriceSaleStrategy.SalesConfig memory sale = signatureMinter.sale(address(target), newTokenId);
    //     assertEq(sale.pricePerToken, 0);
    //     assertEq(sale.saleStart, 0);
    //     assertEq(sale.saleEnd, 0);
    //     assertEq(sale.maxTokensPerAddress, 0);
    //     assertEq(sale.fundsRecipient, address(0));
    // }

    // function test_fixedPriceSaleSupportsInterface() public {
    //     assertTrue(signatureMinter.supportsInterface(0x6890e5b3));
    //     assertTrue(signatureMinter.supportsInterface(0x01ffc9a7));
    //     assertFalse(signatureMinter.supportsInterface(0x0));
    // }
}
