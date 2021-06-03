// SPDX-License-Identifier: GPLv2
//TODO: upgrade to solidity 8
pragma solidity ^0.5.17;
import "@openzeppelin/contracts/math/SafeMath.sol";
import "@openzeppelin/contracts/ownership/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/upgrades/contracts/upgradeability/ProxyFactory.sol";

interface IPersonal {
    function initialize(
        address payable _investor, 
        address _strategist, 
        uint256 _riskLevel,
        address _networkNativeToken,
        address _yieldToken
    ) external;
}

interface IERC20Permit {
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
}

interface IFork {
    function routerAddress() external returns (address);
}

interface ITokenExchangeRouter {
    function swapExactTokensForETH(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

contract Factory is ProxyFactory, Ownable, ReentrancyGuard {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    struct Exchange{
        string name;//name is to identify exchange type. Useful for scripts
        address inContractAddress;
        address outContractAddress;
    }

    struct AddressInfo{
        string description;//brief info about address. May be helpfull for clients
        uint256 riskLevel;//percentage, 33 = 33%, no decimals
        bool approvedForStaticFunctions;
        bool approvedForDirectCallFunction;
    }

    Exchange[] exchanges;
    mapping (address => AddressInfo) public addresses;
    mapping (address => address[]) public personalContracts;

    address contractToConvertTokens;
    uint256 public version = 1;
    uint256 public onRewardNativeDevelopmentFund = 500;//5.00%
    uint256 public onRewardNativeBurn = 500;//5.00%
    uint256 public onRewardYieldDevelopmentFund = 250;//2.50%
    uint256 public onRewardYieldBurn = 250;//2.50%
    address public developmentFund;//this address collects_developmentFund
    uint256 public yieldStakeExchange = 1;//default: UNISWAP or PANCAKESWAP
    address public yieldStakeContract;
    address public yieldStakePair;
    address public personalLibImplementation;
    address public networkNativeToken;//WETH or WBNB
    address public yieldToken;
    bool public skipApprove;//set true if there is no appropriate pool approval functionality implemented
        
    event PersonalContractsCreated(address _investorAddress, address personalContractAddress, address tokenToInvest, uint256 riskLevel);

    constructor (
        address _developmentFund,
        address _personalLibImplementation,
        address _networkNativeToken,
        address _yieldToken,
        address _yieldStakeContract,
        address _yieldStakePair
    ) public {
        require(_developmentFund != address(0), '_developmentFund is empty');
        require(_personalLibImplementation != address(0), '_personalLibImplementation is empty');
        require(_networkNativeToken != address(0), '_networkNativeToken is empty');
        require(_yieldToken != address(0), '_yieldToken is empty');

        developmentFund = _developmentFund;
        networkNativeToken = _networkNativeToken;
        yieldToken = _yieldToken;
        personalLibImplementation = _personalLibImplementation;

        yieldStakeContract = _yieldStakeContract;
        yieldStakePair = _yieldStakePair;

        //example of pre-approved addresses
        //addresses[0xeaB819E2BE63FFC0dF64E7BBA4DDB3bDEa280310] = AddressInfo('Pancake:BUSD-BNB', 25, true, true);
        //addresses[0x221ED06024Ee4296fB544a44cfEDDf7c9f882cF3] = AddressInfo('Pancake:ETH-BNB', 55, true, true);


        exchanges.push(Exchange('', address(0), address(0)));//hardcoded reminder to skip index 0

        //example of pre-defined exhanges
        //exchanges.push(Exchange('PancakeswapV2', 0xe40d348D677530b5692150Fe6C98bb06749723E4, 0x2C501Ac9271b2Dc3D14A152979aE7B32ED0BeE7C));
        //contractToConvertTokens = 0xe40d348D677530b5692150Fe6C98bb06749723E4;
    }

    /**
    @notice This function is used to return total amount of exchanges added
    @return count of exchanges
    */
    function exchangesCount() external view returns (uint256){
        return exchanges.length - 1;//because we skipped 0 index
    }

    /**
    @notice This function is used to return addresses of Liquidity Helper contracts
    @notice This contracts help us to buy/sell LP tokens in one transaction
    @param _exchangeIndex is liquidity pool index, starts from 1
    @return exchange name, in and out address
    */
    function getExchange(uint256 _exchangeIndex) external view returns (string memory, address, address) {
        return (
            exchanges[_exchangeIndex].name, 
            exchanges[_exchangeIndex].inContractAddress, 
            exchanges[_exchangeIndex].outContractAddress
        );
    }

    
    /**
    @notice This function is used to return total amount of personal contract created by one user
    @return count of personal contracts
    */
    function personalContractsCount(address _user) external view returns (uint256){
        return personalContracts[_user].length;
    }

    /**
    @notice This function is used to return "in" liquidity helper contract address.
    @param _exchangeIndex is liquidity pool index, starts from 1
    @return address of the contract. reverts if not set (to prevent any losses)
    */
    function getInContract(uint256 _exchangeIndex) external view returns (address) {
        address _inContractAddress = exchanges[_exchangeIndex].inContractAddress;//saves gas
        require(_inContractAddress != address(0), "inContractAddress is not set");
        return _inContractAddress;
    }

    /**
    @notice This function is used to return "out" liquidity helper contract address.
    @param _exchangeIndex is liquidity pool index, starts from 1
    @return address of the contract. reverts if not set (to prevent any losses)
    */
    function getOutContract(uint256 _exchangeIndex) external view returns (address) {
        address _outContractAddress = exchanges[_exchangeIndex].outContractAddress;//saves gas
        require(_outContractAddress != address(0), "outContractAddress is not set");
        return _outContractAddress;
    }
    

    /**
    @notice This function allows to create personal contract for a user by owner
    @notice for more details see _createPersonalContract() function
    */
    function createPersonalContractForUser(
        address payable _investorAddress, 
        address payable _strategistAddress, 
        uint256 _strategistEth,
        address _tokenToInvest,
        uint256 _riskLevel,
        uint256 _amountToPersonalContract,
        uint256 _amountToStrategist
    ) onlyOwner nonReentrant payable external returns (address) {
        return _createPersonalContract(
            _investorAddress, 
            _strategistAddress, 
            _strategistEth, 
            _tokenToInvest, 
            _amountToPersonalContract, 
            _amountToStrategist,
            _riskLevel,
            0,
            0,
            0
        );
    }

    /**
    @notice creates personal contract along with erc20 token transfer in one transaction
    @notice for more details see _createPersonalContract() function
    */
    function createPersonalContractWithPermit(
        address payable _strategistAddress, 
        uint256 _strategistEth,         
        address _tokenToInvest,
        uint256 _amountToPersonalContract,
        uint256 _amountToStrategist, 
        uint256 _riskLevel,
        uint8 v, 
        bytes32 r, 
        bytes32 s
    ) nonReentrant payable external returns (address) {
        return _createPersonalContract(
            msg.sender, 
            _strategistAddress, 
            _strategistEth, 
            _tokenToInvest,
            _amountToPersonalContract,
            _amountToStrategist,
            _riskLevel,
            v, 
            r, 
            s
        );
    }

    /**
    @notice most simple way to create personal contract
    @notice for more details see _createPersonalContract() function
    */
    function createPersonalContract(
        address payable _strategistAddress,
        uint256 _strategistEth,
        address _tokenToInvest,
        uint256 _amountToPersonalContract,
        uint256 _amountToStrategist,
        uint256 _riskLevel
    ) nonReentrant payable external returns (address) {
        return _createPersonalContract(
            msg.sender, 
            _strategistAddress, 
            _strategistEth, 
            _tokenToInvest,
            _amountToPersonalContract,
            _amountToStrategist,
            _riskLevel,
            0, 
            0, 
            0
        );
    }

    /**
    @notice This function allows to create personal contract for a user by owner
    @notice Along with contract creation owner can send eth / erc20 token that will be transferred to personal contract
    @notice Implementation of the ERC20 Permit extension allowing approvals to be made via signatures, as defined in https://eips.ethereum.org/EIPS/eip-2612
    @param _investorAddress this address will be able to claim all funds and rewards
    @param _strategistAddress personal contract will allow invest commands only from this address
    @param _strategistEth how much of eth should be sent to strategist address (if any). This eth is used to pay for gas fees
    @param _tokenToInvest address of an ERC20 token to invest (0x0 if ether)
    @param _amountToPersonalContract how much of ERC20 (if any) will be transfer to the personal contract
    @param _amountToStrategist how much of ERC20 (if any) will be converted to eth and sent to the strategist address
    @param _riskLevel personal contract will work with pools only if their risk level is less than this variable. 0-100%
    @param v signature param, see eip-2612
    @param r signature param, see eip-2612
    @param s signature param, see eip-2612
    @return address of the contract. reverts if failed to create
    */
    function _createPersonalContract(
        address payable _investorAddress, 
        address payable _strategistAddress, 
        uint256 _strategistEth, 
        address _tokenToInvest,
        uint256 _amountToPersonalContract,
        uint256 _amountToStrategist,
        uint256 _riskLevel,
        uint8 v, 
        bytes32 r, 
        bytes32 s
    ) internal returns (address) {
        require(_investorAddress != address(0), 'EMPTY_INVESTOR_ADDRESS');
        //require(personalContracts[_investorAddress] == address(0), 'CONTRACT_EXISTS');

        address payable personalContractAddress = address(uint160(clonePersonalLibrary()));
        require(personalContractAddress != address(0), 'personalContractAddress is 0x00..');

        IPersonal(personalContractAddress).initialize(_investorAddress, _strategistAddress, _riskLevel, networkNativeToken, yieldToken);
        personalContracts[_investorAddress].push(personalContractAddress);

        if(msg.value > 0){
            if(_strategistEth > 0){
                require(_strategistEth < msg.value, '_strategistEth >= msg.value');
                _strategistAddress.transfer(_strategistEth);   
            }
            //personalContractAddress.transfer(msg.value.sub(_strategistEth));
            sendValue(personalContractAddress, msg.value.sub(_strategistEth));
        }
        if(address(_tokenToInvest) != address(0)){

            if(v > 0){//permittable token 
                //function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
                IERC20Permit(_tokenToInvest).permit(
                    msg.sender, 
                    address(this), 
                    _amountToPersonalContract.add(_amountToStrategist), 
                     uint256(-1), 
                     v, 
                     r, 
                     s
                );
            }

            if(_amountToPersonalContract > 0){
                IERC20(_tokenToInvest).safeTransferFrom(_investorAddress, personalContractAddress, _amountToPersonalContract);
            }

            if(_amountToStrategist > 0){
                IERC20(_tokenToInvest).safeTransferFrom(_investorAddress, address(this), _amountToStrategist);
                convertTokenToETH(_strategistAddress, _tokenToInvest, _amountToStrategist);
            }

        }

        emit PersonalContractsCreated(_investorAddress, personalContractAddress, _tokenToInvest, _riskLevel);
        return personalContractAddress;
    }

    /**
    @notice Convert tokens to eth or wbnb
    @param _toWhomToIssue personal contract will work with pools only if their risk level is less than this variable. 0-100%
    @param _tokenToExchange personal contract will work with pools only if their risk level is less than this variable. 0-100%
    @param _amount personal contract will work with pools only if their risk level is less than this variable. 0-100%
    */
    function convertTokenToETH(address _toWhomToIssue, address _tokenToExchange, uint256 _amount) internal {

        address router = IFork(getContractToConvertTokens()).routerAddress();
            
        IERC20(_tokenToExchange).approve(router, _amount);

        address[] memory path = new address[](2);
        path[0] = _tokenToExchange;
        path[1] = networkNativeToken;//WETH or WBNB
        ITokenExchangeRouter(router).swapExactTokensForETH(
            _amount,
            1,
            path,
            _toWhomToIssue,
            block.timestamp
        );
    }
    
    /**
    @notice in case any changes on Uniswap, Sushiswap, Curve and so on..
    @notice Please refer to personalLibrary if interface functions are match
    @param _exchangeIndex is liquidity pool index, starts from 1
    @param _in new address of "YZapIn" contract
    @param _out new address of "YZapOut" contract
    */
    function changeContracts(uint256 _exchangeIndex, address _in, address _out) onlyOwner external {
        exchanges[_exchangeIndex].inContractAddress = _in;
        exchanges[_exchangeIndex].outContractAddress = _out;
    }

    /**
    @notice in case new platform required. Pickle for example
    @param name the new platform identification (optional)
    @param _in new address of "YZapIn" contract
    @param _out new address of "YZapOut" contract
    */
    function addExchange(string calldata name, address _in, address _out) onlyOwner external {
        require(_in != address(0), 'in address is empty');
        require(_out != address(0), 'out address is empty');
        exchanges.push(Exchange(name, _in, _out));
    }

    
    /**
    @notice This function is used to SET address of a contract where convertTokenToETH(address,address,uint256) can be called.
    @notice by default this function is located in UniswapV2_YZapIn.sol or PancakeswapV2_YZapIn.sol
    @param _contractToConvertTokens is the contract address
    */
    function setContractToConvertTokens(address _contractToConvertTokens) onlyOwner external {
        require(_contractToConvertTokens != address(0), 'address is empty');
        contractToConvertTokens = _contractToConvertTokens;
    }

   /**
    @notice This function is used to GET address of contract, where convertTokenToETH(address,address,uint256) can be called.
    @return address of the contract. reverts if not set
    */
    function getContractToConvertTokens() public view returns (address) {
        require(address(0) != contractToConvertTokens, 'address is not set');
        return contractToConvertTokens;
    }

    /**
    @notice allows set different personal library for new users.  
    @param _implementation address of personal lib
    */
    function setPersonalLibImplementation(address _implementation) onlyOwner external {
        require(_implementation != address(0));
        personalLibImplementation = _implementation;
    }


    /**
    @param _developmentFund new development fund address
    */
    function setDevelopmentFund(address _developmentFund) onlyOwner external {
        require(_developmentFund != address(0));
        developmentFund = _developmentFund;
    }

    function setOnRewardNativeFee(uint256 _onRewardNativeDevelopmentFund, uint256 _onRewardNativeBurn) onlyOwner external {
        onRewardNativeDevelopmentFund = _onRewardNativeDevelopmentFund;
        onRewardNativeBurn = _onRewardNativeBurn;
    }

    /**
    @notice set perentage of tokens that should be transferred to development fund on claim reward function call (in personal contract)
    @param _onRewardYieldDevelopmentFund to develpment fund, 500 = 5%
    @param _onRewardYieldBurn buy & burn yeild tokens, 500 = 5%
    */
    function setOnRewardYieldFee(uint256 _onRewardYieldDevelopmentFund, uint256 _onRewardYieldBurn) onlyOwner external {
        onRewardYieldDevelopmentFund = _onRewardYieldDevelopmentFund;
        onRewardYieldBurn = _onRewardYieldBurn;
    }

    /**
    @notice personal contract will need this for staking rewards tokens into yield pool. 
    @param _yieldStakeContract address of the pool
    @param _yieldStakePair address of the lp pair to stake
    @param _yieldStakeExchange exhange index where lp pair can be minted
    */
    function setYieldStakeContracts(address _yieldStakeContract, address _yieldStakePair, uint256 _yieldStakeExchange) onlyOwner external {
        yieldStakeContract = _yieldStakeContract;
        yieldStakePair = _yieldStakePair;
        yieldStakeExchange = _yieldStakeExchange;
    }


   /**
    @notice in case someone mistakenly sends tokens to the factory, we can send it back via this method
    @return true or false
    */
    function rescueTokens(address tokenAddress, address sendTo, uint256 amount) onlyOwner external returns (bool){
        return IERC20(tokenAddress).transfer(sendTo, amount);
    }

    /**
    @notice the function supposed to be used when governance voting implemented.
    @param _address is pool or vault address
    @param _description is brief info about the pool, optional
    @param _riskLevel personal contract will work with pools only if their risk level is more than this variable. 0-100%
    @param _approvedForStaticFunctions is true if strategist can call pre defined functions
    @param _approvedForDirectCallFunction is true if strategist can call any functions
    */
    function setAddressInfo(
        address _address, 
        string calldata _description, 
        uint256 _riskLevel, 
        bool _approvedForStaticFunctions, 
        bool _approvedForDirectCallFunction
    ) onlyOwner external {
        addresses[_address] = AddressInfo(_description, _riskLevel, _approvedForStaticFunctions, _approvedForDirectCallFunction);
    }


    /**
    @notice used by personal contract. Static calls mean predefined number of functions. Strategist can not call custom transaction
    @notice it is safe to send riskLevel here, cause the function is called by contract
    @return true if prool is approved and client's riskLevel higher than the pool's one
    */
    function isAddressApprovedForStaticFunctions(address _address, uint256 riskLevel) view external returns (bool){
        return  skipApprove || (addresses[_address].approvedForStaticFunctions && addresses[_address].riskLevel <= riskLevel);
    }

    /**
    @notice used by personal contract. Direct calls mean that strategist can call any function with any parameters in the pool
    @notice it is safe to send riskLevel here, cause the function is called by contract
    @return true if prool is approved and client's riskLevel higher than the pool's one
    */
    function isAddressApprovedForDirectCallFunction(address _address, uint256 riskLevel) view external returns (bool){
        return  skipApprove || (addresses[_address].approvedForDirectCallFunction && addresses[_address].riskLevel <= riskLevel);
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     *
     * _Available since v2.4.0._
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(
            address(this).balance >= amount,
            "Address: insufficient balance"
        );

        // solhint-disable-next-line avoid-call-value
        (bool success, ) = recipient.call.value(amount)("");
        require(
            success,
            "Address: unable to send value, recipient may have reverted"
        );
    }

    /**
    @notice deploy personal cont. https://blog.openzeppelin.com/deep-dive-into-the-minimal-proxy-contract/
    @return address of deployed personal lib
    */
    function clonePersonalLibrary() internal returns (address) {
        return deployMinimal(personalLibImplementation, "");
    }
    
    function() external payable {
        revert("Do not send ETH directly");
    }

}