# ZG9rcGFyazIx

## Scope

<table>
  <tr>
    <th>Name</th>
    <td>Dex Security Audit</td>
  </tr>
  <tr>
    <th>Target / Version</th>
    <td>Git Repository (<a href="https://bit.ly/4grf5pU" target="_blank">DEX_Lending_solidity</a>): commit <mark>7c149b1257ebb4ec30925da15c2e9821c4db5037</mark> (<mark>main</mark> branch)</td>
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