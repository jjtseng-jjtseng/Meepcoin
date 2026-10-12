// Experimental v17 policy. Activation requires the explicit isolated testnet build.
// ASERT integer polynomial from the BCH ASERT specification (GNU All-Permissive).
// Copyright (c) 2020 The Bitcoin Cash developers; adaptation copyright (c) 2026 MeepCoin.
// Copying and distribution of this file, with or without modification, are
// permitted in any medium without royalty provided this notice is preserved.
// This file is offered as-is, without any warranty.
#pragma once
#include "cryptonote_basic/difficulty.h"
#include "cryptonote_config.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <algorithm>
#include <limits>
namespace cryptonote {
constexpr uint8_t MEEPCOIN_ASERT_VERSION = 17;
constexpr uint32_t MEEPCOIN_ASERT_HALF_LIFE = 900;
constexpr uint64_t MEEPCOIN_ASERT_FLOOR = 20;
constexpr size_t MEEPCOIN_ASERT_TIMESTAMP_WINDOW = 11;
constexpr uint64_t MEEPCOIN_ASERT_FUTURE_LIMIT = 120;
// Parent is at height p; genesis is height zero. The ideal parent timestamp
// is genesis_time + p*60. Genesis work itself remains one for DB compatibility.
// Signed 256-bit intermediates cover every uint64 timestamp and height.
inline difficulty_type meepcoin_asert_difficulty(uint64_t parent_height,
    uint64_t parent_time, uint64_t genesis_time) {
  using boost::multiprecision::int256_t;
  using boost::multiprecision::uint256_t;
  const difficulty_type maximum = std::numeric_limits<difficulty_type>::max();
  const int256_t numerator = (int256_t(parent_height)*60 -
      (int256_t(parent_time)-genesis_time))*65536;
  const int256_t exponent = numerator/MEEPCOIN_ASERT_HALF_LIFE; // truncate toward zero
  if (exponent <= -145*65536) return MEEPCOIN_ASERT_FLOOR;
  if (exponent >= 128*65536) return maximum;
  const int64_t e=exponent.convert_to<int64_t>();
  int64_t shifts=e/65536;
  int64_t fraction=e%65536;
  if(fraction<0){--shifts;fraction+=65536;}
  const uint256_t f=static_cast<uint64_t>(fraction);
  const uint256_t factor=65536+((uint256_t(195766423245049ULL)*f+
      uint256_t(971821376ULL)*f*f+uint256_t(5127)*f*f*f+(uint256_t(1)<<47))>>48);
  uint256_t scaled=uint256_t(MEEPCOIN_ASERT_FLOOR)*factor;
  if(shifts>=0) {
    if(scaled>((uint256_t(maximum)<<16)>>shifts)) return maximum;
    scaled<<=shifts;
  } else scaled>>=-shifts;
  scaled>>=16;
  if(scaled<MEEPCOIN_ASERT_FLOOR) return MEEPCOIN_ASERT_FLOOR;
  return scaled.convert_to<difficulty_type>();
}
inline bool meepcoin_add_chainwork(difficulty_type parent, difficulty_type work, difficulty_type& result) {
  if (work > std::numeric_limits<difficulty_type>::max() - parent) return false;
  result = parent + work;
  return true;
}
inline size_t meepcoin_timestamp_count(uint8_t version) {
  return version>=MEEPCOIN_ASERT_VERSION?MEEPCOIN_ASERT_TIMESTAMP_WINDOW:BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;
}
inline uint64_t meepcoin_future_limit(uint8_t version) {
  return version>=MEEPCOIN_ASERT_VERSION?MEEPCOIN_ASERT_FUTURE_LIMIT:CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT;
}
}
