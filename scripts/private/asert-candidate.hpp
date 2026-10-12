// UNACTIVATED research candidate. No production call sites or network rule changes.
// Adapts the integer cubic 2^x approximation from BCH's CC0/GNU-All-Permissive
// ASERT specification to MeepCoin's difficulty integer (not BCH target/nBits).
// https://bitcoin-cash-node.gitlab.io/bchn-sw/bitcoincash-upgrade-specifications/2020-11-15-asert/
#pragma once
#include <boost/multiprecision/cpp_int.hpp>
#include <cstdint>
#include <stdexcept>
namespace meepcoin_candidate {
using boost::multiprecision::uint128_t;
using boost::multiprecision::uint256_t;
using boost::multiprecision::int256_t;
inline uint128_t asert(uint128_t anchor,uint64_t height_delta,int64_t time_delta,uint32_t half_life) {
  if(anchor==0||half_life==0)throw std::invalid_argument("positive anchor and half-life required");
  const uint256_t maximum=(uint256_t(1)<<128)-1;
  const int256_t exponent=((int256_t(height_delta)*60-time_delta)*65536)/half_life;
  if(exponent<=-int256_t(145)*65536)return 1;
  if(exponent>=int256_t(128)*65536)return maximum.convert_to<uint128_t>();
  const int64_t e=exponent.convert_to<int64_t>();
  int64_t shifts=e/65536;if(e<0&&e%65536)--shifts;
  const uint64_t fraction=uint64_t(e-shifts*65536);
  const uint256_t f=fraction;
  const uint256_t factor=65536+((195766423245049ULL*f+971821376ULL*f*f+5127ULL*f*f*f+(uint256_t(1)<<47))>>48);
  uint256_t scaled=uint256_t(anchor)*factor;
  if(shifts>=0) {
    if(scaled>((maximum<<16)>>shifts))return maximum.convert_to<uint128_t>();
    scaled<<=shifts;
  }else scaled>>=-shifts;
  scaled>>=16;
  if(scaled<1)return 1;
  return scaled.convert_to<uint128_t>();
}
}
