// Copyright (c) 2017-2022, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <boost/algorithm/string.hpp>
#include "misc_log_ex.h"
#include "util.h"
#include "dns_utils.h"
#include "updates.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "updates"

// MeepCoin: THE UPDATE SUPPLY CHAIN IS REMOVED, NOT REDIRECTED.
//
// Monero's implementation asked the updates.moneropulse.* TXT records for "<software>:<buildtag>:
// <version>:<sha256>" and built a download URL under downloads.getmonero.org / updates.getmonero.org.
// Inherited by a fork, that is a standing authority for another project to name the next binary this
// software offers to install.
//
// Both functions now fail closed. check_updates() performs no DNS lookup, clears its outputs and
// reports "no update"; get_update_url() returns an empty string so no caller can accidentally hand a
// URL to a downloader or print one to an operator. The endpoint literals are deleted from this
// translation unit -- deliberately, so that `strings` on a built binary shows their absence.
//
// No replacement domain, key, URL or binary is invented here. A MeepCoin update channel needs a
// signing authority and a release process that do not exist yet, and inventing placeholders would
// create exactly the false confidence this change removes.

namespace tools
{
  bool check_updates(const std::string &software, const std::string &buildtag, std::string &version, std::string &hash)
  {
    (void)software;
    (void)buildtag;
    version.clear();
    hash.clear();
    MDEBUG("MeepCoin: update checking is not supported; no DNS lookup was performed");
    return false;
  }

  std::string get_update_url(const std::string &software, const std::string &subdir, const std::string &buildtag, const std::string &version, bool user)
  {
    (void)software;
    (void)subdir;
    (void)buildtag;
    (void)version;
    (void)user;
    return std::string();
  }
}
