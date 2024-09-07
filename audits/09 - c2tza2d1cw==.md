# c2tza2d1cw==

## Scope

<table>
  <tr>
    <th>Name</th>
    <td>Dex Security Audit</td>
  </tr>
  <tr>
    <th>Target / Version</th>
    <td>Git Repository (<a href="https://bit.ly/47jGJ3P" target="_blank">Dex_solidity</a>): commit <mark>1487df3439ea6e198f14032db91347bb0dbb1c0a</mark> (<mark>main</mark> branch)</td>
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

또, 유동성 공급이 아래와 같이 기존 *Pool* 의 자산 비율과 관계없이 이루어질 수 있음

```solidity
function testArbitaryAddLiquidity() external {
    uint256 lpReturn = dex.addLiquidity(1000 ether, 2000 ether, 0);
    emit log_named_uint("lpReturn", lpReturn); // lpReturn: 1414213562373095048801

    vm.prank(address(1));
    // arbitary value 12312312312313213123123 ether and 1 ether is provided to pool.
    uint256 lpReturnByAddressOne = dex.addLiquidity(12312312312313213123123 ether, 1 ether, 0);
    emit log_named_uint("lpReturnByAddressOne", lpReturnByAddressOne); // Liquidity Providing Succeed Here, lpReturnByAddressOne: 707106781186547524
}
```

#### Impact

**High**

공격자가 *Pool* 내 자산을 탈취할 수 있음.

#### Recommendation

*CPMM DEX* 구현 간에 `K`(*Constant Value*) 값의 도입 등, 전반적인 *Pool* 내 자산 비율 *Calculation* 정교화 및 고도화 요망.

### #2 `002` Reentrancy in the `swap()` may lead to an overdraw of the deposited amount

|ID|Summary|Severity|
|:---:|-------|:---:|
|002|일반적인 *DEX*의 구현이 각각의 *Pool*을 인스턴스로 생성하는 *Factory Contract*를 통해 이루어지는 점에서, `swap()` 등의 함수에서 해당 *Pool*의 자산이 ERC20 Compatible함과 동시에 별도의 Hook 및 Callback이 존재하는 경우 Reentrancy를 활용한 공격이 있을 수 있음.|High|

#### Description

일반적인 *DEX*의 구현이 각각의 *Pool*을 인스턴스로 생성하는 *Factory Contract*를 통해 이루어지는 점에서, 해당 컨트랙트 또한 그러한 방식을 취한다면, ERC20 Compatible함과 동시에 ERC-777의 `tokensReceived()` 함수와 같은 별도의 Hook 및 Callback이 존재하는 토큰을 *Pool* 내 자산으로 설정하는 경우 `swap()` 함수에 re-enter 할 수 있고, 이에 Reentrancy를 활용한 공격이 있을 수 있음. 특히, `swap()` 함수 내부에서 `_update()` 함수의 호출을 통해 *Pool*의 자산이 갱신되는데, `transfer()` 호출을 통해 토큰의 이동 후에 `update()` 함수의 호출이 이루어지므로, 재진입 시에 해당 *Pool*의 `reserve0` 및 `reserve1` 상태 변수의 값이 제대로 반영되지 못한 상태로 재진입이 이루어짐. 이에 재진입을 방지하도록 *Uniswap V2* 등에서 사용되는 *mutex* 형태의 `lock()`과 같은 *modifier*의 도입이 필요함.

#### Impact

**High**

공격자가 *Pool* 내 모든 자산을 탈취할 수 있음.

#### Recommendation

Reentrancy를 활용한 공격을 방지하기 위해, *mutex* 형태의 Reentrancy Guard 도입 요망.

### #3 `003` The *LP token* is managed solely by a `uint256` type variable

|ID|Summary|Severity|
|:---:|-------|:---:|
|003|*LP Token*의 관리가 별도의 토큰 스탠다드를 따르는 형태가 아닌, `uint256` 타입의 `totalSupply` 변수로 이루어짐.|Informational|

#### Description

해당 컨트랙트는 *LP Token*의 공급을 별도의 *ERC-20* 토큰의 상속 및 활용을 통한 형태로 구현한 것이 아닌, 단지 `uint256` 타입의 `totalSupply` 변수를 통해 관리하고 있음. 특히, `addLiquidity()` 및 `removeLiquidity()` 함수에서는, 유동성 공급이 이루어 졌을 때, 단순히 더하기 및 빼기 연산으로 *LP Token*의 전체 유통량을 증감시키는데, 만약 *Pool*의 전체 유동성이 `type(uint256).max` 값에 도달하면 어떠한 에러 핸들링 없이 유동성 공급이 불가함.

#### Impact

**Informational**

예기치 못한 유동성 공급 불가로 인한 부작용.

#### Recommendation

별도의 *ERC-20* (*Uniswap V2*의 경우) 및 *ERC-721*(*Uniswap V3*의 경우) 등의 형태로 *LP Token* 구현 요망