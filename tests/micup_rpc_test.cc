#include "runtime/micup_rpc.h"

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

#include "mocktail/mocktail_rust.h"
#include "runtime/roblox_experience_presence.h"

namespace mocktail::runtime {
namespace {

constexpr char kWebSocketGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

std::string ComputeWebSocketAccept(const std::string& client_key) {
  const std::string concat = client_key + kWebSocketGuid;
  unsigned char sha1_digest[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const unsigned char*>(concat.data()), concat.size(),
       sha1_digest);
  char encoded[64];
  const int len = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(encoded),
                                  sha1_digest, SHA_DIGEST_LENGTH);
  return std::string(encoded, static_cast<std::size_t>(len));
}

bool ReadExact(int fd, void* dst, std::size_t len) {
  auto* out = static_cast<uint8_t*>(dst);
  std::size_t done = 0;
  while (done < len) {
    const ssize_t n = ::recv(fd, out + done, len - done, 0);
    if (n <= 0) {
      return false;
    }
    done += static_cast<std::size_t>(n);
  }
  return true;
}

bool WriteAll(int fd, const void* src, std::size_t len) {
  const auto* in = static_cast<const uint8_t*>(src);
  std::size_t done = 0;
  while (done < len) {
    const ssize_t n = ::send(fd, in + done, len - done, 0);
    if (n <= 0) {
      return false;
    }
    done += static_cast<std::size_t>(n);
  }
  return true;
}

bool SendWsText(int fd, const std::string& text) {
  std::vector<uint8_t> frame;
  frame.push_back(0x81);
  if (text.size() < 126) {
    frame.push_back(static_cast<uint8_t>(text.size()));
  } else {
    frame.push_back(126);
    frame.push_back(static_cast<uint8_t>((text.size() >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(text.size() & 0xFF));
  }
  frame.insert(frame.end(), text.begin(), text.end());
  return WriteAll(fd, frame.data(), frame.size());
}

struct WsFrame {
  uint8_t opcode = 0;
  std::string payload;
};

bool ReadWsFrame(int fd, WsFrame* out) {
  uint8_t header[2];
  if (!ReadExact(fd, header, 2)) {
    return false;
  }
  out->opcode = header[0] & 0x0F;
  const bool masked = (header[1] & 0x80) != 0;
  uint64_t len = header[1] & 0x7F;
  if (len == 126) {
    uint8_t ext[2];
    if (!ReadExact(fd, ext, 2)) return false;
    len = (static_cast<uint64_t>(ext[0]) << 8) | ext[1];
  } else if (len == 127) {
    uint8_t ext[8];
    if (!ReadExact(fd, ext, 8)) return false;
    len = 0;
    for (int i = 0; i < 8; ++i) {
      len = (len << 8) | ext[i];
    }
  }
  uint8_t mask[4] = {};
  if (masked && !ReadExact(fd, mask, 4)) {
    return false;
  }
  std::string payload(static_cast<std::size_t>(len), '\0');
  if (len > 0 && !ReadExact(fd, payload.data(), payload.size())) {
    return false;
  }
  if (masked) {
    for (std::size_t i = 0; i < payload.size(); ++i) {
      payload[i] = static_cast<char>(payload[i] ^ mask[i % 4]);
    }
  }
  out->payload = std::move(payload);
  return true;
}

int CreateLoopbackListener(uint16_t* port_out) {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  int opt = 1;
  (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
      ::listen(fd, 4) != 0) {
    ::close(fd);
    return -1;
  }
  socklen_t len = sizeof(addr);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
    ::close(fd);
    return -1;
  }
  *port_out = ntohs(addr.sin_port);
  return fd;
}

bool AcceptWsConnection(int listener_fd, int* client_fd_out) {
  const int client = ::accept(listener_fd, nullptr, nullptr);
  if (client < 0) return false;
  std::string request;
  char ch = '\0';
  while (request.size() < 8192) {
    const ssize_t n = ::recv(client, &ch, 1, 0);
    if (n <= 0) {
      ::close(client);
      return false;
    }
    request.push_back(ch);
    if (request.size() >= 4 &&
        request.compare(request.size() - 4, 4, "\r\n\r\n") == 0) {
      break;
    }
  }
  const std::string key_header = "Sec-WebSocket-Key:";
  const std::size_t pos = request.find(key_header);
  if (pos == std::string::npos) {
    ::close(client);
    return false;
  }
  const std::size_t start =
      request.find_first_not_of(" \t", pos + key_header.size());
  const std::size_t end = request.find("\r\n", start);
  const std::string client_key = request.substr(start, end - start);
  const std::string response =
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: " +
      ComputeWebSocketAccept(client_key) + "\r\n\r\n";
  if (!WriteAll(client, response.data(), response.size())) {
    ::close(client);
    return false;
  }
  *client_fd_out = client;
  return true;
}

TEST(MicupRpcTest, BuildsSanitizedManualAndCatalogActivities) {
  std::array<char, 513> json_buf{};
  std::size_t out_len = 0;

  const std::string mode_auto = "auto";
  const std::string browsing = "Browsing Roblox";
  const std::string joining = "Joining an experience";
  const std::string playing = "{place_name}";
  const std::string unknown = "Unknown experience";
  const std::string dirty_title = "Tower \xEF\xB8\x8F\nDefense";

  ASSERT_EQ(mocktail_rust_micup_build_activity_json(
                mode_auto.data(), mode_auto.size(), 1, 1, browsing.data(),
                browsing.size(), joining.data(), joining.size(), playing.data(),
                playing.size(), unknown.data(), unknown.size(), 2,
                dirty_title.data(), dirty_title.size(), 1700000000000LL,
                1700000050000LL, json_buf.data(), json_buf.size(), &out_len),
            0);
  const nlohmann::json parsed =
      nlohmann::json::parse(std::string(json_buf.data(), out_len));
  EXPECT_EQ(parsed.at("manual_name"), "Tower Defense");
  EXPECT_EQ(parsed.at("started_at"), 1700000000000LL);

  const std::string mode_catalog = "catalog";
  ASSERT_EQ(mocktail_rust_micup_build_activity_json(
                mode_catalog.data(), mode_catalog.size(), 1, 0, browsing.data(),
                browsing.size(), joining.data(), joining.size(), playing.data(),
                playing.size(), unknown.data(), unknown.size(), 2,
                dirty_title.data(), dirty_title.size(), 1700000000000LL,
                1700000050000LL, json_buf.data(), json_buf.size(), &out_len),
            0);
  const nlohmann::json catalog =
      nlohmann::json::parse(std::string(json_buf.data(), out_len));
  EXPECT_EQ(catalog.at("game_id"), "roblox");
  EXPECT_EQ(catalog.at("started_at"), 1700000050000LL);
}

TEST(MicupRpcTest, DisabledPolicyStartsWithoutTokenAndObserverFanoutDelivers) {
  MicupRpcConfig disabled;
  disabled.enabled = false;
  MicupRpcSession session(disabled);
  std::string detail;
  EXPECT_TRUE(session.Start(&detail));
  EXPECT_EQ(detail, "disabled by runtime policy");

  struct Recorder {
    int count = 0;
    RobloxExperiencePresencePhase last_phase =
        RobloxExperiencePresencePhase::kBrowsing;
  } a, b;

  auto record = [](void* ctx, RobloxExperiencePresencePhase phase,
                   const RobloxExperienceLaunchRequest*) {
    auto* r = static_cast<Recorder*>(ctx);
    ++r->count;
    r->last_phase = phase;
  };

  RobloxExperiencePresenceObserverFanout fanout;
  fanout.Add({&a, record});
  fanout.Add({&b, record});
  const RobloxExperiencePresenceObserver combined = fanout.observer();
  ASSERT_TRUE(combined.valid());
  combined.notify(combined.context, RobloxExperiencePresencePhase::kPlaying,
                  nullptr);
  EXPECT_EQ(a.count, 1);
  EXPECT_EQ(b.count, 1);
  EXPECT_EQ(a.last_phase, RobloxExperiencePresencePhase::kPlaying);
  EXPECT_EQ(b.last_phase, RobloxExperiencePresencePhase::kPlaying);
}

TEST(MicupRpcTest, EnabledWithoutTokenFailsCleanly) {
  MicupRpcConfig missing;
  missing.enabled = true;
  MicupRpcSession session(missing);
  std::string detail;
  EXPECT_FALSE(session.Start(&detail));
  EXPECT_NE(detail.find("token"), std::string::npos);
}

TEST(MicupRpcTest, LiveGatewaySessionLoadsTokenFilePublishesAndClears) {
  const std::filesystem::path token_file =
      std::filesystem::temp_directory_path() /
      ("mocktail-micup-token-" + std::to_string(::getpid()) + ".txt");
  {
    std::ofstream out(token_file);
    out << "cpp-loopback-token\n";
  }

  uint16_t port = 0;
  const int listener = CreateLoopbackListener(&port);
  ASSERT_GE(listener, 0);

  std::mutex frames_mu;
  std::condition_variable frames_cv;
  std::vector<nlohmann::json> client_frames;
  auto wait_frames = [&](std::size_t count) {
    std::unique_lock<std::mutex> lock(frames_mu);
    ASSERT_TRUE(frames_cv.wait_for(
        lock, std::chrono::seconds(5),
        [&]() { return client_frames.size() >= count; }));
  };

  std::thread server([&]() {
    int client = -1;
    ASSERT_TRUE(AcceptWsConnection(listener, &client));
    ASSERT_TRUE(SendWsText(
        client, R"({"op":10,"d":{"heartbeat_interval":30000}})"));

    WsFrame frame;
    ASSERT_TRUE(ReadWsFrame(client, &frame));
    {
      std::lock_guard<std::mutex> lock(frames_mu);
      client_frames.push_back(nlohmann::json::parse(frame.payload));
      frames_cv.notify_all();
    }

    ASSERT_TRUE(SendWsText(
        client,
        R"({"op":0,"s":1,"t":"READY","d":{"session_id":"cpp-sid","user_settings":{"status":"online"},"sessions":[{"session_id":"cpp-sid","status":"invisible"}]}})"));

    while (ReadWsFrame(client, &frame)) {
      if (frame.opcode == 0x8) {
        break;
      }
      if (frame.opcode == 0x1) {
        std::lock_guard<std::mutex> lock(frames_mu);
        client_frames.push_back(nlohmann::json::parse(frame.payload));
        frames_cv.notify_all();
      }
    }
    ::close(client);
  });

  MicupRpcConfig cfg;
  cfg.enabled = true;
  cfg.gateway_url = "ws://127.0.0.1:" + std::to_string(port) + "/gateway";
  cfg.token_file = token_file.string();
  cfg.status = "auto";
  cfg.activity_mode = "auto";
  cfg.show_place_name = false;

  MicupRpcSession session(cfg);
  std::string detail;
  ASSERT_TRUE(session.Start(&detail)) << detail;

  wait_frames(2);
  RobloxExperienceLaunchRequest launch;
  launch.place_id = 123456;
  const RobloxExperiencePresenceObserver obs = session.observer();
  obs.notify(obs.context, RobloxExperiencePresencePhase::kPlaying, &launch);
  wait_frames(3);

  session.Stop();
  server.join();
  ::close(listener);
  std::error_code ec;
  std::filesystem::remove(token_file, ec);

  ASSERT_GE(client_frames.size(), 4U);
  EXPECT_EQ(client_frames[0].at("op"), 2);
  EXPECT_EQ(client_frames[0].at("d").at("token"), "cpp-loopback-token");

  EXPECT_EQ(client_frames[1].at("op"), 3);
  EXPECT_EQ(client_frames[1].at("d").at("status"), "online");
  EXPECT_EQ(client_frames[1].at("d").at("game_activity").at("manual_name"),
            "Browsing Roblox");

  EXPECT_EQ(client_frames[2].at("op"), 3);
  EXPECT_EQ(client_frames[2].at("d").at("game_activity").at("game_id"),
            "roblox");

  EXPECT_EQ(client_frames.back().at("op"), 3);
  EXPECT_TRUE(client_frames.back().at("d").at("game_activity").is_null());
}

}  // namespace
}  // namespace mocktail::runtime
