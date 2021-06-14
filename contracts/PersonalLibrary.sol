// SPDX-License-Identifier: GPLv2
//TODO: upgrade to solidity 8
pragma solidity ^0.5.17;
pragma experimental ABIEncoderV2;
import "@openzeppelin/contracts/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20Burnable.sol";

interface IYZapIn {
    function YZapIn(
        address _toWhomToIssue,
        address _fromTokenAddress,
        address _toPairAddress,
        uint256 _amount,
        uint256 _minPoolTokens
    ) external payable returns (uint256);


    function YZapInAndStake(
        address fromTokenAddress,
        address stakeContractAddress,
        uint256 amount,
        uint256 minStakeTokens
    ) external payable returns (uint256);
}

interface YZap {
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

    
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);

    function swapExactETHForTokens(
        uint amountOutMin, 
        address[] calldata path, 
        address to, 
        uint deadline
    ) external payable returns (uint[] memory amounts);
}

interface IYZapOut {
    function YZapOut(
        address _toWhomToIssue,
        address _toTokenAddress,
        address _fromPoolAddress,
        uint256 _amount,
        uint256 _minToTokens
    ) external payable returns (uint256);

    //for curve only
    function getTokenAddressFromSwapAddress(
        address _fromPairAddress
    ) external view returns (address);
}

interface IStakeOrDepositPool {
    function stake(uint256 amount) external;
    function deposit(uint256 amount) external;
    function withdraw(uint256 amount) external;
    function getReward() external;
    function exit() external;
}

interface IStakeOrDepositPoolWithPID {
    function deposit(uint256 pid, uint256 amount) external;
    function withdraw(uint256 pid, uint256 amount) external;
}

interface IYIELDPool {
    function stakeAndAssignTo(address assignTo, uint256 amount) external;
    function withdraw(uint256 amount) external;
    function getReward() external;
    function exit() external;
}

interface IVaultProxy {
    function deposit(uint256 amount) external;
    function withdraw(uint256 amount) external;
}


interface IFactory {
    function directCallAddresses(address _address) external returns (bool);
    function getContractToConvertTokens() external returns (address);
    function getInContract(uint256 _exchange) external returns (address);
    function getOutContract(uint256 _exchange) external returns (address);
    function isAddressApprovedForStaticFunctions(address _address, uint256 riskLevel) external view returns (bool);
    function isAddressApprovedForDirectCallFunction(address _address, uint256 riskLevel) external view returns (bool);
    function yieldStakeContract() external view returns (address);
    function yieldStakePair() external view returns (address);
    function yieldStakeExchange() external view returns (uint256);
    function developmentFund() external view returns (address payable);
    function onRewardNativeDevelopmentFund() external view returns (uint256);//5.00%
    function onRewardNativeBurn() external view returns (uint256);//5.00%
    function onRewardYieldDevelopmentFund() external view returns (uint256);//2.50%
    function onRewardYieldBurn() external view returns (uint256);//2.50%
}

interface IWBNBWETH {
    function deposit() external payable;
    function withdraw(uint256 wad) external;
}

/**
@notice Personal contract, used by Factory contract. 
@notice Contains all functions needed for investments
@notice Contains all functions needed for investments
@notice variable investor is owner of deposit funds
@notice variable strategist is address used to run investment commands
@notice variable factory address of factory contract
@notice variable pairInvestmentHistory get log history [by address]
@notice variable Investments get log history [by index]
*/
contract PersonalLibrary {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    enum PoolTemplate{ STAKE, DEPOSIT, DEPOSIT_WITH_PID, STAKE_WITH_PID }
    //note: we use PoolTemplate for Vault too, cause enum set is equal

    uint256 public version = 1;
    address payable public investor;
    address public strategist;
    address public factory;
    //address public personalLib;
    address yieldToken;
    address networkNativeToken;//WETH or WBNB
    mapping (address => uint256) public pairInvestmentHistory;
    mapping (uint256 => address[]) public Investments;
    event ValueReceived(address user, uint amount, address token);
    uint256 constant percentageDecimals = 10000;//two => 100.00%
    uint256 public riskLevel;

    bool private _notEntered;

    event RewardStaked(uint256 lpAmount, address[] tokens);
    event RewardNativeClaimed(uint256 yieldBurn, uint256 ethToDevelopment, uint256 amountToInvestor);
    event RewardYieldClaimed(uint256 yieldBurn, uint256 amountToConvertToETH, uint256 amountToInvestor);
    event LiquidityUnstakedAndWithdrawn(address stakePool);


    struct ProvideLiquiditySet {
        uint256 exchange;
        address tokenAddress;
        address pairAddress;
        address liquidityPoolOutputTokenAddress;
        uint256 amount;
        uint256 minPoolTokens;
    }

    struct LiquidityToVaultSet {
        PoolTemplate poolTemplate;
        address vaultAddresses;
    }

    struct StakeSet {
        PoolTemplate poolTemplate; 
        address stakeContractAddress; 
        address tokenToStake;
        uint256 pid;
    }
    
    struct UnstakeSet {
        PoolTemplate poolTemplate;
        address stakeContractAddress; 
        uint256 amount;
        uint256 pid;
    }

    struct VaultToLiquiditySet {
        address vaultAddress;
    }

    struct WithdrawLiquiditySet {
        uint256 exchange;
        address toWhomToIssue;
        address toTokenAddress;
        address fromTokenAddress;
        address fromliquidityPoolAddress;
        uint256 minTokensRec;
    }
    
    /**
     * @dev Throws if called by any account other than the strategist.
     */
    modifier onlyStrategist() {
        require(msg.sender == strategist, "!strategist");
        _;
    }

    modifier strategistOrInvestor() {
        require(msg.sender == strategist || msg.sender == investor, "!strategist!investor");
        _;
    }

    /**
     * @dev Throws if called by any account other than the investor.
     */
    modifier onlyInvestor() {
        require(msg.sender == investor, '!investor');
        _;
    }

    /**
     * @dev simple custom ReentrancyGuard solution cause
     * failed to run ReentrancyGuard from openzeppelin with initialize/ProxyFactory 
     * (due to private _notEntered and constructor)
     */
    modifier nonReentrant() {
        require(_notEntered, 'already entered');
        _notEntered = false;
        _;
        _notEntered = true;
    }
    
    /**
    @notice This function is called only once for every new personal contract
    @param _investor can deposit and withdraw funds
    @param _strategist can invest available funds
    @param _riskLevel max risk level for this contract (0-100%)
    @param _networkNativeToken address of WETH or WBNB
    @param _yieldToken address of Yield Protocol token
    */
    function initialize (
        address payable _investor, 
        address _strategist, 
        uint256 _riskLevel,
        address _networkNativeToken,
        address _yieldToken
    ) public {
        require(factory == address(0), 'contract is already initialized');
        factory = msg.sender;
        investor = _investor;
        strategist = _strategist;
        riskLevel = _riskLevel;
        networkNativeToken = _networkNativeToken;
        yieldToken = _yieldToken;
        _notEntered = true;//cause no pre defined variables on ProxyFactory
    }
    
    /**
    @notice This function is used to invest in given LP pair through ETH/ERC20 Tokens
    @param _exchange is liquidity pool index taken from Factory contract
    @param _ToWhomToIssue is address of personal contract for this user
    @param _fromTokenAddress The ERC20 token used for investment (address(0x00..) if ether)
    @param _toPairAddress The liquidity pool pair address
    @param _amount The amount of fromToken to invest
    @param _minPoolTokens Reverts if less tokens received than this
    @return Amount of LP bought
    */
    function provideLiquidity(
        uint256 _exchange, 
        address _ToWhomToIssue,
        address _fromTokenAddress, 
        address _toPairAddress, 
        uint256 _amount, 
        uint256 _minPoolTokens
    ) public strategistOrInvestor returns (uint256) {
        require(_ToWhomToIssue == address(this) || _ToWhomToIssue == investor, '!allowed');
        logNewPair(_exchange, _toPairAddress);

        address inContract = IFactory(factory).getInContract(_exchange);
        uint256 ethValue;

        if(_fromTokenAddress == address(0)){
            ethValue = _amount;
        }else{
            _approve(_fromTokenAddress, inContract, _amount);
        }

        return IYZapIn(inContract).YZapIn.value(ethValue)(
            _ToWhomToIssue,
            _fromTokenAddress,
            _toPairAddress,
            _amount,
            _minPoolTokens
        );
    }

    /**
    @notice This function is used to withdraw liquidity from pool
    @param _exchange is liquidity pool index taken from Factory contract
    @param _ToWhomToIssue is address of personal contract for this user
    @param _ToTokenContractAddress The ERC20 token to withdraw in (address(0x00) if ether)
    @param _fromPairAddress The pair address to withdraw from
    @param _amount The amount of liquidity pool tokens (LP)
    @param _minTokensRec Reverts if less tokens received than this
    @return the amount of eth/tokens received after withdraw
    */
    function withdrawLiquidity(
        uint256 _exchange,
        address _ToWhomToIssue,
        address _ToTokenContractAddress,
        address _fromPairAddress,
        uint256 _amount,
        uint256 _minTokensRec
    ) public payable strategistOrInvestor nonReentrant returns (uint256){
        require(_ToWhomToIssue == address(this) || _ToWhomToIssue == investor, '!allowed');

        uint256 tokenBought = YZapOut(
            _ToWhomToIssue,
            _exchange,
            _ToTokenContractAddress,
            _fromPairAddress,
            _amount,
            _minTokensRec
        );
        return tokenBought;
    }


    
    /**
    @notice the function stakes token into provided pool.
    @notice pool's "stake" function must match one of hardcoded template
    @param _poolTemplate template of the pool. 0 = STAKE, 1 = DEPOSIT and so on..
    @param _stakeContractAddress The stake contract address
    @param _tokenToStake is address of a token or lp/flp pair to be staked
    @param _amount The amount of _fromTokenAddress to invest
    @param _pid id of the pool in masterchef contract..
    */
    function stake(PoolTemplate _poolTemplate, address _stakeContractAddress, address _tokenToStake, uint256 _amount, uint256 _pid) onlyStrategist public {

        require(IFactory(factory).isAddressApprovedForStaticFunctions(_stakeContractAddress, riskLevel), 'address is not approved');

        _approve(_tokenToStake, _stakeContractAddress, _amount);

        if(_poolTemplate == PoolTemplate.STAKE){
            IStakeOrDepositPool(_stakeContractAddress).stake(_amount);
        }else if(_poolTemplate == PoolTemplate.DEPOSIT){
            IStakeOrDepositPool(_stakeContractAddress).deposit(_amount);
        }else if(_poolTemplate == PoolTemplate.DEPOSIT_WITH_PID){
            IStakeOrDepositPoolWithPID(_stakeContractAddress).deposit(_pid, _amount);
        }

        //no need to check this, since we will get revert on function call if provided pool is wrong 
        //revert('stake: wrong pool template');
    }

    /**
    @notice This function is used to unstake tokens
    @param _poolTemplate template of the pool. 0 = STAKE, 1 = DEPOSIT and so on..
    @param _stakeContractAddress The stake contract address
    @param _amount The amount of tokens to withdraw
    @param _pid id of the pool in masterchef contract..
    */
    function unstake(PoolTemplate _poolTemplate, address _stakeContractAddress, uint256 _amount, uint256 _pid) public strategistOrInvestor {

        if(_poolTemplate == PoolTemplate.DEPOSIT_WITH_PID){
            IStakeOrDepositPoolWithPID(_stakeContractAddress).withdraw(_pid, _amount);
            //getReward called automatically
        }else{
            IStakeOrDepositPool(_stakeContractAddress).withdraw(_amount);
            IStakeOrDepositPool(_stakeContractAddress).getReward();
        }
    }
    
    /**
    @notice This function is used to farm tokens, example: 3Crv -> f3Crv
    @notice Didn't include PoolTemplate.DEPOSIT_WITH_PID, cause no vault found with such deposit
    @param _poolTemplate template of the pool. 0 = STAKE, 1 = DEPOSIT.
    @param _vaultAddresses address of the Vault where to deposit lp
    @param _fromPairAddress is a sours of lp tokens
    @param _amount amount of lp tokens to farm
    */
    function liquidityToVault(
        PoolTemplate _poolTemplate, 
        address _vaultAddresses, 
        address _fromPairAddress, 
        uint256 _amount
    ) public onlyStrategist {

      _approve(_fromPairAddress, _vaultAddresses, _amount);

        if(_poolTemplate == PoolTemplate.STAKE){
            IStakeOrDepositPool(_vaultAddresses).stake(_amount);
        }else if(_poolTemplate == PoolTemplate.DEPOSIT){
            IStakeOrDepositPool(_vaultAddresses).deposit(_amount);
        }

        //no need to check this, since we will get revert on function call if provided pool is wrong 
        //revert('liquidityToVault: wrong pool template');
    }

    /**
    @notice This function is used to unfarm flp tokens, example: f3Crv -> 3Crv
    @notice Didn't add _poolTemplate, cause all known use same withdraw function
    @param vaultAddress source of farmed tokens
    */
    function vaultToLiquidity(address vaultAddress) public strategistOrInvestor {
        IVaultProxy(vaultAddress).withdraw(IERC20(vaultAddress).balanceOf(address(this)));
    }


    /********* Wrapper section *******/

    
    /**
    @notice This function is used to exchange liquidity pool tokens in one transaction
    @param _fromExchange is liquidity pool index taken from Factory contract
    @param _fromPairAddress source pair address of lp tokens
    @param _toExchange is liquidity pool index taken from Factory contract
    @param _toPairAddress new pair address of lp tokens
    @param _amount The amount of liquidity pool tokens (LP)
    @param _minPoolTokens Reverts if less tokens received than this
    @return Amount of LP bought
    */
    function swapLiquidity(
        uint256 _fromExchange,
        address _fromPairAddress,
        uint256 _toExchange,
        address _toPairAddress,
        uint256 _amount,
        uint256 _minPoolTokens
    ) public onlyStrategist returns (uint256) {

        logNewPair(_toExchange, _toPairAddress);

        uint256 intermediateAmount = YZapOut(
            address(this),
            _fromExchange,
            networkNativeToken,
            _fromPairAddress,
            _amount,
            1
        );

        return provideLiquidity(
            _toExchange,
            address(this),
            networkNativeToken,
            _toPairAddress,
            intermediateAmount,
            _minPoolTokens
        );
    
    }

    
    /**
    @notice This function is used to provide liquidity and stake with one transaction [harvest]
    @param _pl is a struct of variables that will be used in provideLiquidity function
    @param _lv ... liquidityToVault function
    @param _st ... stake function
    */
    function provideLiquidityAndStake(
        ProvideLiquiditySet memory _pl,
        LiquidityToVaultSet memory _lv,
        StakeSet memory _st
    ) public onlyStrategist {
        uint256 balance = _pl.amount;

        if(_pl.exchange > 0){
            balance = provideLiquidity(_pl.exchange, address(this), _pl.tokenAddress, _pl.pairAddress, _pl.amount, _pl.minPoolTokens);
        }else if(_pl.tokenAddress != _pl.pairAddress){
            balance = _pl.tokenAddress != address(0) 
            ? convertTokenToToken(address(this), _pl.tokenAddress, _pl.pairAddress, _pl.amount)
            : convertETHToToken(address(this), _pl.pairAddress, _pl.amount);
        }
        
        if(_lv.vaultAddresses != address(0)){
            liquidityToVault(_lv.poolTemplate, _lv.vaultAddresses, _pl.liquidityPoolOutputTokenAddress, balance);
            balance = IERC20(_st.tokenToStake).balanceOf(address(this));
        }

        if(_st.stakeContractAddress != address(0)){
            stake(_st.poolTemplate, _st.stakeContractAddress, _st.tokenToStake, balance, _st.pid);
        }
    }

    /**
    @notice This function is used to unstake and withdraw liquidity with one transaction [harvest]
    @param _un is a struct of variables that will be used in unstake function
    @param _vl ... vaultToLiquidity function
    @param _wl ... withdrawLiquidity function
    */
    function unstakeAndWithdrawLiquidity(
        UnstakeSet memory _un,
        VaultToLiquiditySet memory _vl,
        WithdrawLiquiditySet memory _wl
    ) public strategistOrInvestor {

        if(_un.stakeContractAddress != address(0)){
            unstake(_un.poolTemplate, _un.stakeContractAddress, _un.amount, _un.pid);
        }

        if(_vl.vaultAddress != address(0)){
            vaultToLiquidity(_vl.vaultAddress);
        }

        if(_wl.exchange > 0){
            withdrawLiquidity(
                _wl.exchange, 
                _wl.toWhomToIssue,
                _wl.toTokenAddress, 
                _wl.fromTokenAddress, 
                IERC20(_wl.fromliquidityPoolAddress).balanceOf(address(this)), 
                _wl.minTokensRec
            );
        }else if(_wl.toTokenAddress != _wl.fromTokenAddress){
            uint256 _balance = IERC20(_wl.fromTokenAddress).balanceOf(address(this));
            if(_wl.toTokenAddress != address(0)){
                convertTokenToToken(_wl.toWhomToIssue, _wl.fromTokenAddress, _wl.toTokenAddress, _balance);
            }else{
                convertTokenToETH(_wl.toWhomToIssue, _wl.fromTokenAddress, _balance);
            }
        }

        emit LiquidityUnstakedAndWithdrawn(_un.stakeContractAddress);
    }

    /**
    @notice simple wrapper to claim & exit in one transaction
    @param _rewardType reward function selector
    */
    function unstakeAndWithdrawLiquidityAndClaimReward(
        UnstakeSet memory _un,
        VaultToLiquiditySet memory _vl,
        WithdrawLiquiditySet memory _wl,
        uint256 _rewardType,
        address[] memory _tokens, 
        address[] memory _pools
    ) public onlyInvestor {
        unstakeAndWithdrawLiquidity(_un, _vl, _wl);

        if(_rewardType == 1){
            claimRewardNativeTokens(_tokens,  _pools);
        }else if(_rewardType == 2){
            claimRewardYIELDTokens(_tokens,  _pools);
        }else if(_rewardType == 3){
            stakeReward(_tokens, _pools);
        }
    }

    /**
    @notice This function is used to combine several transactions into one action: restake
    @param _un is a struct of variables that will be used in unstake function
    @param _vl ... vaultToLiquidity function
    @param _wl ... withdrawLiquidity function
    @param _pl ... provideLiquidity function
    @param _lv ... liquidityToVault function
    @param _st ... stake function
    */
    function restake(
        UnstakeSet memory _un,
        VaultToLiquiditySet memory _vl,
        WithdrawLiquiditySet memory _wl,
        ProvideLiquiditySet memory _pl,
        LiquidityToVaultSet memory _lv,
        StakeSet memory _st
    ) public {

        //additional info:
        //_wl.toWhomToIssue - no need, always this contract
        //_wl_minTokensRec - doesn't metter, we have _pl.minPoolTokens
        //_wl.toTokenAddress - should be networkNativeToken or liquidityPoolOutputTokenAddress
        //_pl.tokenAddress == _wl.toTokenAddress
        //_pl.amount - we need to calculate this

        _wl.toWhomToIssue = address(this);
        if(_pl.exchange == 0){
             //no lp pair try to withdraw directly in required token
            _wl.toTokenAddress = _pl.liquidityPoolOutputTokenAddress;
        }else{
            //have to work with lp pairs
            //TODO: try to add direct swap
            _wl.toTokenAddress = networkNativeToken;
        }
        
        unstakeAndWithdrawLiquidity(
            _un, 
            _vl, 
            _wl
        );

        _pl.amount = IERC20(_wl.toTokenAddress).balanceOf(address(this));
        _pl.tokenAddress = _wl.toTokenAddress;

        provideLiquidityAndStake(
            _pl,
            _lv, 
            _st
        );
    }

    /**
    @notice 10% FEE - Claim your rewards in the native token you earned. 
    @notice 5% of those will go towards Buying and BURNING YIELD tokens, 
    @notice the other 5% will go to YFarmer to fund its future development
    @param _tokens array of reward token addresses to claim
    @param _pools array of staked pools. Helpful if it is needed to get 
    */
    function claimRewardNativeTokens(address[] memory _tokens, address[] memory _pools) onlyInvestor public {

        for (uint256 i; i < _pools.length; i++){
            IStakeOrDepositPool(_pools[i]).getReward();
        }

        uint256 rewardAmount;
        uint256 yieldBurn;
        uint256 ethToDevelopment;
        uint256 amountToInvestor;
        for (uint256 i; i < _tokens.length; i++){

            rewardAmount = IERC20(_tokens[i]).balanceOf(address(this));
            if(rewardAmount == 0) continue;

            yieldBurn = rewardAmount.sub(rewardAmount.mul(percentageDecimals.sub(IFactory(factory).onRewardNativeBurn())).div(percentageDecimals));
            ethToDevelopment = rewardAmount.sub(rewardAmount.mul(percentageDecimals.sub(IFactory(factory).onRewardNativeDevelopmentFund())).div(percentageDecimals));
            amountToInvestor = rewardAmount.sub(yieldBurn).sub(ethToDevelopment);

            IERC20(_tokens[i]).safeTransfer(
                investor,
                amountToInvestor
            );

            ethToDevelopment = convertTokenToETH(IFactory(factory).developmentFund(), _tokens[i], ethToDevelopment);
            
            //yieldBurn = convertTokenToYIELD(address(this), _tokens[i], yieldBurn);
            yieldBurn = convertTokenToToken(address(this), _tokens[i], yieldToken, yieldBurn);
            ERC20Burnable(yieldToken).burn(yieldBurn);

            emit RewardNativeClaimed(yieldBurn, ethToDevelopment, amountToInvestor);
        }
        
    }


    /**
    @notice 5% FEE - Claim your rewards in YIELD tokens - 
    @notice 97.5% of your reward tokens will be used to market-buy YIELD,
    @notice and 2.5% of those will be burnt
    @param _tokens array of reward token addresses to claim
    @return amount of burned tokens, amount of tokens transferred to investor
    */
    function claimRewardYIELDTokens(address[] memory _tokens, address[] memory _pools) onlyInvestor public returns (uint256, uint256) {

        for (uint256 i; i < _pools.length; i++){
            IStakeOrDepositPool(_pools[i]).getReward();
        }

        //note: we don't expect small amounts of tokens here
        uint256 rewardAmount = convertRewardTokensToYIELD(address(this), _tokens);

        uint256 yieldBurn = rewardAmount.sub(rewardAmount.mul(percentageDecimals.sub(IFactory(factory).onRewardYieldBurn())).div(percentageDecimals));
        uint256 amountToConvertToETH = rewardAmount.sub(rewardAmount.mul(percentageDecimals.sub(IFactory(factory).onRewardYieldDevelopmentFund())).div(percentageDecimals));
        uint256 amountToInvestor = rewardAmount.sub(yieldBurn).sub(amountToConvertToETH);
        
        amountToConvertToETH = convertTokenToETH(IFactory(factory).developmentFund(), yieldToken, amountToConvertToETH);

        IERC20(yieldToken).safeTransfer(investor, amountToInvestor);
        ERC20Burnable(yieldToken).burn(yieldBurn);

        emit RewardYieldClaimed(yieldBurn, amountToConvertToETH, amountToInvestor);

        return (yieldBurn, amountToInvestor);
        
    }

    /**
    @notice set new stop loss level for this personal contract, 
    @notice please don't set this  
    @param _riskLevel is new risk level value (0 - 100 value, no decimals)
    */
    function setRiskLevel(uint256 _riskLevel) onlyInvestor external {
        riskLevel = _riskLevel;
    }

    /**
    @notice 0% FEE - Claim your rewards int LP tokens - 50% of the reward tokens will be used to buy YIELD, 
    @notice 50% will be used to buy ETH - and automatically added to the YIELD/ETH pool -
    @notice which will earn you more YIELD in staking rewards.
    @param _tokens array of reward token addresses to claim
    @return Amount of LP bought
    */
    function stakeReward(address[] memory _tokens, address[] memory _pools) onlyInvestor public returns (uint256) {

        for (uint256 i; i < _pools.length; i++){
            IStakeOrDepositPool(_pools[i]).getReward();
        }

        uint256 amountOfTokens = convertRewardTokensToYIELD(address(this), _tokens);
        //require(yieldTokenTokens > 0, 'yieldTokenTokens is empty');

        address stakePair = IFactory(factory).yieldStakePair();        
        uint256 providedLiquidity = provideLiquidity(
            IFactory(factory).yieldStakeExchange(), 
            investor,
            yieldToken, 
            stakePair, 
            amountOfTokens, 
            1
        );

        //TODO: uncomment this when pool deployed
        //TODO: change investor to address(this) in provideLiquidity function
        /*address stakeContract = IFactory(factory).yieldStakeContract();
        IERC20(stakePair).approve(
            stakeContract,
            providedLiquidity
        );*/

        //IStakeOrDepositPool(stakeContract).stake(providedLiquidity);
        //IyieldTokenPool(stakeContract).stakeAndAssignTo(investor, providedLiquidity);

        emit RewardStaked(providedLiquidity, _tokens);

        return providedLiquidity;
    }

    /**
    @notice helper, allows to call any method with any data on the provided address.
    @notice safety is guaranteed by approved pools: we can not call this method on any address; 
    @notice so, fund of the investor still safe
    @notice positive moment of this func is that we can adopt almost instantly to investment flow change.
    @param _address1 address on which we should run provided bytecode
    @param _inuptBytes1 bytecode to call on address 1
    @param _address2 another address, just to do two transactions in one
    @param _inuptBytes2 another bytecode, just to do two transactions in one
    @return result of 1 call, result of 2 call 
    */
    function directCall(address _address1, bytes calldata _inuptBytes1, address _address2, bytes calldata _inuptBytes2) onlyStrategist nonReentrant external returns (bytes memory, bytes memory){
        bool status;
        bytes memory result1;
        bytes memory result2;

        require(IFactory(factory).isAddressApprovedForDirectCallFunction(_address1, riskLevel), 'address1: directCallAddresses is not allowed');

        (status, result1) = _address1.call(_inuptBytes1); 
        require(status, 'call 1 failed');

        if(_address2 != address(0)){
            require(IFactory(factory).isAddressApprovedForDirectCallFunction(_address2, riskLevel), 'address2: directCallAddresses is not allowed');
            (status, result2) = _address2.call(_inuptBytes2); 
            require(status, 'call 2 failed');
        }

        return (result1, result2);
    }

    /**
    @notice emergency eth withdraw. Will take 10% fee.
    @param sendTo address where needed to send eth
    */
    function rescueEth(address payable sendTo) external onlyInvestor nonReentrant {

        uint256 balance = address(this).balance;
        require(balance > 0, 'nothing to rescue');
        sendTo.transfer(balance.sub(balance.div(10)));
        IFactory(factory).developmentFund().transfer(balance.div(10));

    }

    /** internal functions **/

    /**
    @notice convert any tokens to any tokens.
    @param _toWhomToIssue is address of personal contract for this user
    @param _tokenToExchange address of token witch will be converted
    @param _tokenToConvertTo address of token witch will be returned
    @param _amount how much will be converted
    */
    function convertTokenToToken(address _toWhomToIssue, address _tokenToExchange, address _tokenToConvertTo, uint256 _amount) internal returns (uint256) {

        address routerAddress = YZap(IFactory(factory).getContractToConvertTokens()).routerAddress();
        _approve(_tokenToExchange, routerAddress, _amount);

        uint256 length = (_tokenToExchange == networkNativeToken || networkNativeToken == _tokenToConvertTo)?2:3;
        address[] memory path = new address[](length);

        if(length == 3){
            path[0] = _tokenToExchange;
            path[1] = networkNativeToken;
            path[2] = _tokenToConvertTo;
        } else {//in case we don't need networkNativeToken token
            path[0] = _tokenToExchange;
            path[1] = _tokenToConvertTo;
        }

        return ITokenExchangeRouter(routerAddress).swapExactTokensForTokens(
            _amount,
            1,
            path,
            _toWhomToIssue,
            block.timestamp + 3600*24*365
        )[path.length - 1];
        //uint256 constant deadline = block.timestamp + 3600*24*365;//1 year

    }

    /**
    @notice Convert tokens to eth or wbnb
    @param _toWhomToIssue is address of personal contract for this user
    @param _tokenToExchange address of token witch will be converted
    @param _amount how much will be converted
    */
    function convertTokenToETH(address _toWhomToIssue, address _tokenToExchange, uint256 _amount) internal returns (uint256)  {

        address router = YZap(IFactory(factory).getContractToConvertTokens()).routerAddress();

        if(_tokenToExchange == networkNativeToken){
            //means we would like to exchange WETH(WBNB) to ETH(BNB)
            //IWBNBWETH(networkNativeToken).withdraw(_amount); - this reverts due to https://eips.ethereum.org/EIPS/eip-1884[EIP1884]
            //have to do this: WETH -> YIELD TOKEN -> ETH
            _approve(_tokenToExchange, router, _amount);
            _amount = convertTokenToToken(address(this), _tokenToExchange, yieldToken,  _amount);
            _tokenToExchange = yieldToken;
        }

        
            
        _approve(_tokenToExchange, router, _amount);

        address[] memory path = new address[](2);
        path[0] = _tokenToExchange;
        path[1] = networkNativeToken;//WETH or WBNB
        return ITokenExchangeRouter(router).swapExactTokensForETH(
            _amount,
            1,
            path,
            _toWhomToIssue,
            block.timestamp
        )[path.length - 1];
    }

    /**
    @notice Convert eth to token or wbnb
    @param _toWhomToIssue personal contract will work with pools only if their risk level is less than this variable. 0-100%
    @param _tokenToExchange personal contract will work with pools only if their risk level is less than this variable. 0-100%
    */
    function convertETHToToken(address _toWhomToIssue, address _tokenToExchange, uint256 _amount) internal returns (uint256)  {

        if(_tokenToExchange == networkNativeToken){
            //means we would like to exthange ETH(BNB) to WETH(WBNB)
            IWBNBWETH(networkNativeToken).deposit.value(_amount)();
            return _amount;
        }

        address router = YZap(IFactory(factory).getContractToConvertTokens()).routerAddress();

        address[] memory path = new address[](2);
        path[0] = networkNativeToken; //WETH or WBNB
        path[1] = _tokenToExchange; 
        return ITokenExchangeRouter(router).swapExactETHForTokens.value(_amount)(
            1,
            path,
            _toWhomToIssue,
            block.timestamp
        )[path.length - 1];
    }

    /**
    @notice convert array of any tokens to yield tokens.
    @param _toWhomToIssue is address of personal contract for this user
    @param _tokens array of token witch needed to convert to yield
    @return balance of yield tokens in this address 
    */
    function convertRewardTokensToYIELD(address _toWhomToIssue, address[] memory _tokens) internal returns (uint256) {
        
        for (uint256 i; i < _tokens.length; i++){
            //convertTokenToYIELD(_toWhomToIssue, _tokens[i], IERC20(_tokens[i]).balanceOf(address(this)));
            if(_tokens[i] != yieldToken){
                convertTokenToToken(_toWhomToIssue, _tokens[i], yieldToken, IERC20(_tokens[i]).balanceOf(address(this)));
            }
        }

        return IERC20(yieldToken).balanceOf(address(this));        
    }

    /**
    @notice add new pair to investment history.
    @param exchangeIndex index of new exchanges
    @param pairAddress address of new pair
    */
    function logNewPair(uint256 exchangeIndex, address pairAddress) internal {
        if(pairInvestmentHistory[pairAddress] == 0){
            Investments[exchangeIndex].push(pairAddress);
            pairInvestmentHistory[pairAddress] = exchangeIndex;
        }
    }

    function YZapOut(
        address _toWhomToIssue,
        uint256 _exchange,
        address _ToTokenContractAddress,
        address _fromPairAddress,
        uint256 _amount,
        uint256 _minTokensRec
    ) internal returns (uint256) {

        address outContractAddress = IFactory(factory).getOutContract(_exchange);

        address tokenAddress = IYZapOut(outContractAddress).getTokenAddressFromSwapAddress(_fromPairAddress); 
        _approve(tokenAddress, outContractAddress, _amount);

        return IYZapOut(outContractAddress).YZapOut(
            _toWhomToIssue,
            _ToTokenContractAddress,
            _fromPairAddress,
            _amount,
            _minTokensRec
        );
    }

    function _approve(address _token, address _spender, uint256 _amount) internal {

        if(_token == 0xdAC17F958D2ee523a2206206994597C13D831ec7){
            //USDT: https://github.com/Uniswap/uniswap-interface/issues/1172
            IERC20(_token).safeApprove(_spender, 0);
        }

        IERC20(_token).safeApprove(_spender, _amount);
    }

    function() external payable {
         emit ValueReceived(msg.sender, msg.value, address(0));
    }

}