# b29NaWE=

## Scope

<table>
  <tr>
    <th>Name</th>
    <td>Dex Security Audit</td>
  </tr>
  <tr>
    <th>Target / Version</th>
    <td>Git Repository (<a href="https://bit.ly/3XfvxAK" target="_blank">Upside_DEX_solidity</a>): commit <mark>3dc4e1869aa0e942963de705450de1ee9d25f70a</mark> (<mark>main</mark> branch)</td>
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

### #1 `001` The calculation of liquidity and swap ratios may result in the theft of assets from the pool

|ID|Summary|Severity|
|:---:|-------|:---:|
|001|`addLiquidity()` 함수 내에서, *CPMM DEX*의 구현간에 *Pool* 내 자산 비율을 계산하는 데에 단순히 `/` (나누기 연산) 으로 연산하여 `require` 문으로 조건을 확인함. 이는 공격자가 나누기 연산의 몫 조건만을 충족시키는 방식으로 풀 내 자산을 탈취할 수 있음.|High|

#### Description

`addLiquidity()` 함수 내에서 `require(balanceX / amountX == balanceY / amountY);` 와 같은 방식으로 *Pool* 내 자산 비율을 계산하고 있음. 이는 가령, *Pool* 내 기존 자산이 자산 *x*가 *1000* 수량, 자산 *y*가 *2000* 수량 예치되어있을 경우, 공격자가 *x* 자산을 *99* 수량, *y* 자산을 *200* 수량을 추가 예치하는 것이 가능함. 이는 *CPMM DEX*의 구현 상, 본래 의도 된 *x* 자산 *100* 수량 및 *y* 자산 *200* 수량의 비율로 예치하도록 의도한 값과 다른 값임. 그 결과, 공격자는 예치 수량을 임의로 조정하여, `removeLiquidity()`를 통해 *Pool* 내 모든 자산의 탈취가 가능함.

#### Impact

**High**

공격자가 *Pool* 내 모든 자산을 탈취할 수 있음.

#### Recommendation

*CPMM DEX* 구현 간에 `K`(*Constant Value*) 값의 도입 등, 전반적인 *Pool* 내 자산 비율 *Calculation* 정교화 및 고도화 요망.

### #2 `002` Reentrancy in the `swap()` may lead to an overdraw of the deposited amount

|ID|Summary|Severity|
|:---:|-------|:---:|
|002|일반적인 *DEX*의 구현이 각각의 *Pool*을 인스턴스로 생성하는 *Factory Contract*를 통해 이루어지는 점에서, `swap()` 등의 함수에서 해당 *Pool*의 자산이 ERC20 Compatible함과 동시에 별도의 Hook 및 Callback이 존재하는 경우 Reentrancy를 활용한 공격이 있을 수 있음.|High|

#### Description

일반적인 *DEX*의 구현이 각각의 *Pool*을 인스턴스로 생성하는 *Factory Contract*를 통해 이루어지는 점에서, 해당 컨트랙트 또한 그러한 방식을 취한다면, ERC20 Compatible함과 동시에 ERC-777의 `tokensReceived()` 함수와 같은 별도의 Hook 및 Callback이 존재하는 토큰을 *Pool* 내 자산으로 설정하는 경우 `swap()` 함수에 re-enter 할 수 있고, 이에 Reentrancy를 활용한 공격이 있을 수 있음. 이에 그러한 훅의 동작을 방지하도록 *Uniswap V2* 등에서 사용되는 *mutex* 형태의 `lock()`과 같은 *modifier*의 도입이 필요함.

#### Impact

**High**

공격자가 *Pool* 내 모든 자산을 탈취할 수 있음.

#### Recommendation

Reentrancy를 활용한 공격을 방지하기 위해, *mutex* 형태의 Reentrancy Guard 도입 요망.