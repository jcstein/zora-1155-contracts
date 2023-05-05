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
    function isAuthorized(address account) external returns (bool);
}

/// @title ZoraSignatureMinterStrategy
/// @notice Mints tokens based on a merkle tree, for presales for example
/// @author @iainnash / @tbtstl
contract ZoraSignatureMinterStrategy is Enjoy, SaleStrategy, LimitedMintPerAddress {
    using SaleCommandHelper for ICreatorCommands.CommandSet;

    /// @notice General signatue sale settings
    struct SignatureSaleSettings {
        IAuthRegistry authorizedSignatureCreators;
        /// @notice Funds recipient (0 if no different funds recipient than the contract global)
        address fundsRecipient;
    }

    struct SignedMint {
        bool valid;
        bool executed;
    }

    // target -> tokenId -> settings
    mapping(address => mapping(uint256 => SignatureSaleSettings)) signatureSaleSettings;
    // target -> nonce
    mapping(address => uint256) nonces;
    // target -> hash -> signed mints
    mapping(address => mapping(uint256 => SignedMint)) public signedMints;

    /// @notice Event for sale configuration updated
    event SaleSet(address indexed mediaContract, uint256 indexed tokenId, SignatureSaleSettings signatureSaleSettings);

    error SaleEnded();
    error SaleHasNotStarted();
    error WrongValueSent();
    error InvalidSignature(address mintTo);

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

    error MerkleClaimsExceeded();

    /// @notice Compiles and returns the commands needed to mint a token using this sales strategy
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
        (address signer, uint256 nonce, uint256 pricePerToken, uint256 expiration, address mintTo) = abi.decode(
            minterArguments,
            (address, uint256, uint256, uint256, address)
        );

        if (block.timestamp > expiration) {
            revert("Expired");
        }
        // recover signer address from the arguments
        // see if recovered signer matches what was stored
        if (signer == address(0)) revert("Invalid signature");

        uint256 signedMintHash = _hashSignedMint(signer, nonce, tokenId, quantity, pricePerToken, expiration, mintTo);

        SignedMint storage signedMint = signedMints[target][signedMintHash];
        // check and set that signed mint is used
        if (!signedMint.valid) revert("Invalid signed mint");
        if (signedMint.executed) revert("Executed");
        signedMint.executed = true;

        // validate that proper value was sent
        if (quantity * pricePerToken != ethValueSent) {
            revert WrongValueSent();
        }

        return _executeMintAndTransferFunds(target, tokenId, quantity, mintTo, ethValueSent);
    }

    function signMint(address target, uint256 nonce, uint256 tokenId, uint256 quantity, uint256 pricePerToken, uint256 expiration, address mintTo) external {
        // nonce must increment for each target contract address
        require(nonce == nonces[target]++, "Comp::delegateBySig: invalid nonce");

        // signer must be authorized
        bool isAuthorized = signatureSaleSettings[target][tokenId].authorizedSignatureCreators.isAuthorized(msg.sender);

        // now has the mint instructions, and store the mint
        if (!isAuthorized) revert("Cannot sign");

        // generate a hash from the mint parameters
        uint256 signedMintHash = _hashSignedMint(msg.sender, nonce, tokenId, quantity, pricePerToken, expiration, mintTo);
        // mark that its a valid signed mint
        signedMints[target][signedMintHash].valid = true;
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

    function _hashSignedMint(
        address signer,
        uint256 nonce,
        uint256 tokenId,
        uint256 quantity,
        uint256 pricePerToken,
        uint256 expiration,
        address mintTo
    ) private pure returns (uint256) {
        return uint256(keccak256(abi.encode(signer, nonce, tokenId, quantity, pricePerToken, expiration, mintTo)));
    }

    /// @notice Sets the sale configuration for a token
    function setSale(uint256 tokenId, SignatureSaleSettings calldata _signatureSaleSettings) external {
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
    function sale(address tokenContract, uint256 tokenId) external view returns (SignatureSaleSettings memory) {
        return signatureSaleSettings[tokenContract][tokenId];
    }

    /// @notice IERC165 interface
    /// @param interfaceId intrfaceinterface id to match
    function supportsInterface(bytes4 interfaceId) public pure virtual override(LimitedMintPerAddress, SaleStrategy) returns (bool) {
        return super.supportsInterface(interfaceId) || LimitedMintPerAddress.supportsInterface(interfaceId) || SaleStrategy.supportsInterface(interfaceId);
    }
}
