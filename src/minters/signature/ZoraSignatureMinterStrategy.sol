// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {Enjoy} from "_imagine/mint/Enjoy.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {IMinter1155} from "../../interfaces/IMinter1155.sol";
import {ICreatorCommands} from "../../interfaces/ICreatorCommands.sol";
import {SaleStrategy} from "../SaleStrategy.sol";
import {ICreatorCommands} from "../../interfaces/ICreatorCommands.sol";
import {SaleCommandHelper} from "../utils/SaleCommandHelper.sol";
import {LimitedMintPerAddress} from "../utils/LimitedMintPerAddress.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/*


             ░░░░░░░░░░░░░░              
        ░░▒▒░░░░░░░░░░░░░░░░░░░░        
      ░░▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░      
    ░░▒▒▒▒░░░░░░░░░░░░░░    ░░░░░░░░    
   ░▓▓▒▒▒▒░░░░░░░░░░░░        ░░░░░░░    
  ░▓▓▓▒▒▒▒░░░░░░░░░░░░        ░░░░░░░░  
  ░▓▓▓▒▒▒▒░░░░░░░░░░░░░░    ░░░░░░░░░░  
  ░▓▓▓▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░  
  ░▓▓▓▓▓▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░  
   ░▓▓▓▓▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░  
    ░░▓▓▓▓▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░    
    ░░▓▓▓▓▓▓▒▒▒▒▒▒▒▒░░░░░░░░░▒▒▒▒▒░░    
      ░░▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░      
          ░░▓▓▓▓▓▓▓▓▓▓▓▓▒▒░░░          

               OURS TRULY,


    github.com/ourzora/zora-1155-contracts

 */

interface IAuthRegistry {
    function isAuthorized(address account) external view returns (bool);
}

/// @title ZoraSignatureMinterStrategy
/// @notice Mints tokens based on signature created by an authorized signer
/// @author @oveddan
contract ZoraSignatureMinterStrategy is Enjoy, SaleStrategy, LimitedMintPerAddress, EIP712 {
    using SaleCommandHelper for ICreatorCommands.CommandSet;

    /// @notice General signatue sale settings
    struct SalesConfig {
        IAuthRegistry authorizedSignatureCreators;
        /// @notice Funds recipient (0 if no different funds recipient than the contract global)
        address fundsRecipient;
    }

    // target -> tokenId -> settings
    mapping(address => mapping(uint256 => SalesConfig)) signatureSaleSettings;
    // target contract -> unique nonce -> if has been minted already
    mapping(address => mapping(bytes32 => bool)) private minted;

    /// @notice Event for sale configuration updated
    event SaleSet(address indexed mediaContract, uint256 indexed tokenId, SalesConfig signatureSaleSettings);

    error SaleEnded();
    error SaleHasNotStarted();
    error WrongValueSent(uint256 expectedValue, uint256 valueSent);
    error InvalidSignature();
    error AlreadyMinted();
    error Expired(uint256 expiration);

    bytes32 constant REQUEST_MINT_TYPEHASH =
        keccak256("requestMint(address target,uint256 tokenId,bytes32 uid,uint256 quantity,uint256 pricePerToken,uint256 expiration,address mintTo)");

    /// @notice ContractURI for contract information with the strategy
    function contractURI() external pure override returns (string memory) {
        return "https://github.com/ourzora/zora-1155-contracts/";
    }

    /// @notice The name of the sale strategy
    function contractName() external pure override returns (string memory) {
        return "Signature Sale Strategy";
    }

    /// @notice The version of the sale strategy
    function contractVersion() external pure override returns (string memory) {
        return "1.0.0";
    }

    constructor() EIP712("ZoraSignatureMinterStrategy", "1") {}

    error MerkleClaimsExceeded();

    /// @notice Compiles and returns the commands needed to mint a token using this sales strategy.  Requires a signature
    /// to have been created off-chain by an authorized signer.
    /// @param tokenId The token ID to mint
    /// @param quantity The quantity of tokens to mint
    /// @param ethValueSent The amount of ETH sent with the transaction
    /// @param minterArguments The additional arguments passed to the minter including additional mint params and the signature
    function requestMint(
        address,
        uint256 tokenId,
        uint256 quantity,
        uint256 ethValueSent,
        bytes calldata minterArguments
    ) external returns (ICreatorCommands.CommandSet memory) {
        address target = msg.sender;
        // these arguments are what don't fit into the standard requestMint Args
        (bytes32 uid, uint256 pricePerToken, uint256 expiration, address mintTo, bytes memory signature) = abi.decode(
            minterArguments,
            (bytes32, uint256, uint256, address, bytes)
        );

        address signer = _recover(target, tokenId, uid, quantity, pricePerToken, expiration, mintTo, signature);

        // do we need this setting to be there for each token, or just be the same across the board?
        if (signer == address(0) || !isAuthorizedToSign(signer, target, tokenId)) {
            revert InvalidSignature();
        }

        // do we need this to be also unique per signer?
        if (minted[target][uid]) {
            revert AlreadyMinted();
        }
        minted[target][uid] = true;

        // validate that the mint hasn't expired
        if (block.timestamp > expiration) {
            revert Expired(expiration);
        }

        // validate that proper value was sent
        if (quantity * pricePerToken != ethValueSent) {
            revert WrongValueSent(quantity * pricePerToken, ethValueSent);
        }

        return _executeMintAndTransferFunds(target, tokenId, quantity, mintTo, ethValueSent);
    }

    /// Used to create a hash of the data for the requestMint function,
    /// that is to be signed by the authorized signer.
    function delegateCreateContractHashTypeData(
        address target,
        uint256 tokenId,
        bytes32 uid,
        uint256 quantity,
        uint256 pricePerToken,
        uint256 expiration,
        address mintTo
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(REQUEST_MINT_TYPEHASH, target, uid, tokenId, quantity, pricePerToken, expiration, mintTo));

        return _hashTypedDataV4(structHash);
    }

    function _recover(
        address target,
        uint256 tokenId,
        bytes32 uid,
        uint256 quantity,
        uint256 pricePerToken,
        uint256 expiration,
        address mintTo,
        bytes memory signature
    ) private view returns (address) {
        bytes32 digest = delegateCreateContractHashTypeData(target, tokenId, uid, quantity, pricePerToken, expiration, mintTo);

        return ECDSA.recover(digest, signature);
    }

    function isAuthorizedToSign(address signer, address target, uint256 tokenId) public view returns (bool) {
        return signatureSaleSettings[target][tokenId].authorizedSignatureCreators.isAuthorized(signer);
    }

    function _executeMintAndTransferFunds(
        address target,
        uint256 tokenId,
        uint256 quantity,
        address mintTo,
        uint256 ethValueSent
    ) private view returns (ICreatorCommands.CommandSet memory commands) {
        address fundsRecipient = signatureSaleSettings[target][tokenId].fundsRecipient;
        // Should transfer funds if funds recipient is set to a non-default address
        bool shouldTransferFunds = fundsRecipient != address(0);

        // Setup contract commands
        commands.setSize(shouldTransferFunds ? 2 : 1);
        // Mint command
        commands.mint(mintTo, tokenId, quantity);

        // If we have a non-default funds recipient for this token
        if (shouldTransferFunds) {
            commands.transfer(fundsRecipient, ethValueSent);
        }
    }

    /// @notice Sets the sale configuration for a token.  Meant to be called from the erc1155 contract
    function setSale(uint256 tokenId, SalesConfig calldata _signatureSaleSettings) external {
        signatureSaleSettings[msg.sender][tokenId] = _signatureSaleSettings;

        // Emit event for new sale
        emit SaleSet(msg.sender, tokenId, _signatureSaleSettings);
    }

    /// @notice Resets the sale configuration for a token
    function resetSale(uint256 tokenId) external override {
        delete signatureSaleSettings[msg.sender][tokenId];

        // Emit event with empty sale
        emit SaleSet(msg.sender, tokenId, signatureSaleSettings[msg.sender][tokenId]);
    }

    /// @notice Gets the sale configuration for a token
    /// @param tokenContract address to look up sale for
    /// @param tokenId token ID to look up sale for
    function sale(address tokenContract, uint256 tokenId) external view returns (SalesConfig memory) {
        return signatureSaleSettings[tokenContract][tokenId];
    }

    /// @notice IERC165 interface
    /// @param interfaceId intrfaceinterface id to match
    function supportsInterface(bytes4 interfaceId) public pure virtual override(LimitedMintPerAddress, SaleStrategy) returns (bool) {
        return super.supportsInterface(interfaceId) || LimitedMintPerAddress.supportsInterface(interfaceId) || SaleStrategy.supportsInterface(interfaceId);
    }
}
