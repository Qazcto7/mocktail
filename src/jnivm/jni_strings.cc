#include "jni_strings.h"
#include "mocktail/mocktail_rust.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <limits>

#include "jni_references.h"

namespace jnivm::internal {
namespace {
constexpr jchar kEmptyUtf16[] = {0};

void AppendUtf8CodePoint(std::uint32_t code_point, std::string* output) {
  if (code_point <= 0x7f) {
    output->push_back(static_cast<char>(code_point));
  } else if (code_point <= 0x7ff) {
    output->push_back(static_cast<char>(0xc0 | (code_point >> 6)));
    output->push_back(static_cast<char>(0x80 | (code_point & 0x3f)));
  } else if (code_point <= 0xffff) {
    output->push_back(static_cast<char>(0xe0 | (code_point >> 12)));
    output->push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3f)));
    output->push_back(static_cast<char>(0x80 | (code_point & 0x3f)));
  } else {
    output->push_back(static_cast<char>(0xf0 | (code_point >> 18)));
    output->push_back(static_cast<char>(0x80 | ((code_point >> 12) & 0x3f)));
    output->push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3f)));
    output->push_back(static_cast<char>(0x80 | (code_point & 0x3f)));
  }
}

std::string Utf16ToUtf8(const std::vector<jchar>& utf16) {
  std::string output;
  output.reserve(utf16.size());
  for (std::size_t index = 0; index < utf16.size(); ++index) {
    std::uint32_t code_point = utf16[index];
    if (code_point >= 0xd800 && code_point <= 0xdbff &&
        index + 1 < utf16.size() && utf16[index + 1] >= 0xdc00 &&
        utf16[index + 1] <= 0xdfff) {
      code_point =
          0x10000 + ((code_point - 0xd800) << 10) + (utf16[++index] - 0xdc00);
    } else if (code_point >= 0xd800 && code_point <= 0xdfff) {
      code_point = 0xfffd;
    }
    AppendUtf8CodePoint(code_point, &output);
  }
  return output;
}

std::string Utf16ToModifiedUtf8(const std::vector<jchar>& utf16,
                                std::size_t begin = 0,
                                std::size_t count = std::string::npos) {
  if (begin >= utf16.size()) {
    return {};
  }
  const std::size_t end =
      std::min(utf16.size(), begin + std::min(count, utf16.size() - begin));
  const std::size_t slice_len = end - begin;
  std::string output(slice_len * 3, '\0');
  std::size_t out_len = 0;
  if (mocktail_rust_utf16_to_mutf8(
          reinterpret_cast<const uint16_t*>(utf16.data() + begin), slice_len,
          reinterpret_cast<uint8_t*>(output.data()), output.size(),
          &out_len) == 0) {
    output.resize(out_len);
    return output;
  }
  return {};
}

std::vector<jchar> ModifiedUtf8ToUtf16(const char* input) {
  if (input == nullptr) {
    return {};
  }
  const std::size_t size = std::strlen(input);
  std::vector<jchar> output(size + 1);
  std::size_t out_len = 0;
  if (mocktail_rust_mutf8_to_utf16(
          reinterpret_cast<const uint8_t*>(input), size,
          reinterpret_cast<uint16_t*>(output.data()), output.size(),
          &out_len) == 0) {
    output.resize(out_len);
    return output;
  }
  output.resize(size * 2);
  if (mocktail_rust_mutf8_to_utf16(
          reinterpret_cast<const uint8_t*>(input), size,
          reinterpret_cast<uint16_t*>(output.data()), output.size(),
          &out_len) == 0) {
    output.resize(out_len);
    return output;
  }
  return {};
}

static std::vector<jchar> MakeUtf16Vector(const jchar* utf16, jsize length) {
  if (utf16 != nullptr && length > 0) {
    return std::vector<jchar>(utf16, utf16 + length);
  }
  return {};
}

struct PseudoStringObject : PseudoJavaObject {
  PseudoStringObject(std::shared_ptr<Class> cls, const char* utf)
      : PseudoJavaObject(std::move(cls)),
        chars(ModifiedUtf8ToUtf16(utf)),
        value(Utf16ToUtf8(chars)),
        modified_utf8(Utf16ToModifiedUtf8(chars)) {}

  PseudoStringObject(std::shared_ptr<Class> cls, const jchar* utf16,
                     jsize length)
      : PseudoJavaObject(std::move(cls)),
        chars(MakeUtf16Vector(utf16, length)),
        value(Utf16ToUtf8(chars)),
        modified_utf8(Utf16ToModifiedUtf8(chars)) {}

  std::vector<jchar> chars;
  std::string value;
  std::string modified_utf8;
};

}  // namespace

static inline bool IsRawStringPointer(jstring str) {
  const uintptr_t val = reinterpret_cast<uintptr_t>(str);
  if (val < 0x10000) {
    return false;
  }
  if (IsSegmentHandle(reinterpret_cast<jobject>(str))) {
    return false;
  }
  if (ArrayFromRef(reinterpret_cast<jarray>(str)) != nullptr) {
    return false;
  }
  return true;
}

jstring MakeString(const char* utf) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  auto cls = FallbackClassForName("java/lang/String");
  auto object = std::make_unique<PseudoStringObject>(std::move(cls), utf);
  jobject handle = StoreObject(std::move(object));
  jstring str = reinterpret_cast<jstring>(handle);
  g_known_strings.insert(str);
  return str;
}

jstring MakeUtf16String(const jchar* utf16, jsize length) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  auto cls = FallbackClassForName("java/lang/String");
  auto object =
      std::make_unique<PseudoStringObject>(std::move(cls), utf16, length);
  jobject handle = StoreObject(std::move(object));
  jstring str = reinterpret_cast<jstring>(handle);
  g_known_strings.insert(str);
  return str;
}

std::string_view StringViewFromJString(jstring str) {
  if (__builtin_expect(!str, 0)) {
    return {};
  }
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  if (g_known_strings.find(str) != g_known_strings.end()) {
    auto* string_object = dynamic_cast<PseudoStringObject*>(
        PseudoObjectFromRef(reinterpret_cast<jobject>(str)));
    if (string_object != nullptr) {
      return string_object->value;
    }
  }
  if (!IsRawStringPointer(str)) {
    return {};
  }
  const char* utf = reinterpret_cast<const char*>(str);
  return std::string_view(utf);
}

std::string StringFromJString(jstring str) {
  const std::string_view sv = StringViewFromJString(str);
  return std::string(sv);
}

bool IsUtf8CharsetName(jstring charset_name) {
  std::string normalized = StringFromJString(charset_name);
  for (char& character : normalized) {
    if (character >= 'A' && character <= 'Z') {
      character = static_cast<char>(character - 'A' + 'a');
    }
  }
  return normalized == "utf-8" || normalized == "utf8" ||
         normalized == "unicode-1-1-utf-8";
}

std::string JavaStringUtf8Bytes(const std::vector<jchar>& utf16) {
  std::string output;
  output.reserve(utf16.size());
  for (std::size_t index = 0; index < utf16.size(); ++index) {
    std::uint32_t code_point = utf16[index];
    if (code_point >= 0xd800 && code_point <= 0xdbff &&
        index + 1 < utf16.size() && utf16[index + 1] >= 0xdc00 &&
        utf16[index + 1] <= 0xdfff) {
      code_point =
          0x10000 + ((code_point - 0xd800) << 10) + (utf16[++index] - 0xdc00);
    } else if (code_point >= 0xd800 && code_point <= 0xdfff) {
      // CharsetEncoder replaces each malformed UTF-16 unit with '?'.
      output.push_back('?');
      continue;
    }
    AppendUtf8CodePoint(code_point, &output);
  }
  return output;
}

jbyteArray JavaStringGetUtf8Bytes(jobject obj, jstring charset_name) {
  if (!IsUtf8CharsetName(charset_name)) {
    if (TraceEnabled()) {
      std::cerr << "  [JNI] java/lang/String.getBytes rejected unsupported "
                   "charset\n";
    }
    return nullptr;
  }

  std::string bytes;
  {
    std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
    auto* string_object =
        dynamic_cast<PseudoStringObject*>(PseudoObjectFromRef(obj));
    if (string_object == nullptr) {
      return nullptr;
    }
    bytes = JavaStringUtf8Bytes(string_object->chars);
  }
  if (bytes.size() >
      static_cast<std::size_t>(std::numeric_limits<jsize>::max())) {
    return nullptr;
  }

  jbyteArray result = MakeByteArray(static_cast<jsize>(bytes.size()));
  PseudoArray* array = ArrayFromRef(result);
  if (array == nullptr || array->bytes.size() != bytes.size()) {
    return nullptr;
  }
  if (!bytes.empty()) {
    std::memcpy(array->bytes.data(), bytes.data(), bytes.size());
  }
  return result;
}

const char* StringChars(jstring str) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  if (!str) {
    return nullptr;
  }
  if (g_known_strings.find(str) != g_known_strings.end()) {
    auto* string_object = dynamic_cast<PseudoStringObject*>(
        PseudoObjectFromRef(reinterpret_cast<jobject>(str)));
    return string_object != nullptr ? string_object->modified_utf8.c_str() : "";
  }
  if (!IsRawStringPointer(str)) {
    return "";
  }
  return reinterpret_cast<const char*>(str);
}

const jchar* StringUtf16Chars(jstring str) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  if (!str) {
    return nullptr;
  }
  if (g_known_strings.find(str) != g_known_strings.end()) {
    auto* string_object = dynamic_cast<PseudoStringObject*>(
        PseudoObjectFromRef(reinterpret_cast<jobject>(str)));
    return string_object && !string_object->chars.empty()
               ? string_object->chars.data()
               : kEmptyUtf16;
  }
  if (!IsRawStringPointer(str)) {
    return kEmptyUtf16;
  }
  return reinterpret_cast<const jchar*>(str);
}

jsize StringUtf16Length(jstring str) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  if (g_known_strings.find(str) != g_known_strings.end()) {
    auto* string_object = dynamic_cast<PseudoStringObject*>(
        PseudoObjectFromRef(reinterpret_cast<jobject>(str)));
    return string_object != nullptr
               ? static_cast<jsize>(string_object->chars.size())
               : 0;
  }
  if (!IsRawStringPointer(str)) {
    return 0;
  }
  const char* bytes = reinterpret_cast<const char*>(str);
  return bytes != nullptr ? static_cast<jsize>(std::strlen(bytes)) : 0;
}

jsize StringModifiedUtf8Length(jstring str) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  if (g_known_strings.find(str) != g_known_strings.end()) {
    auto* string_object = dynamic_cast<PseudoStringObject*>(
        PseudoObjectFromRef(reinterpret_cast<jobject>(str)));
    return string_object != nullptr
               ? static_cast<jsize>(string_object->modified_utf8.size())
               : 0;
  }
  if (!IsRawStringPointer(str)) {
    return 0;
  }
  const char* bytes = reinterpret_cast<const char*>(str);
  return bytes != nullptr ? static_cast<jsize>(std::strlen(bytes)) : 0;
}

void CopyStringRegion(jstring str, jsize start, jsize length, jchar* output) {
  if (str == nullptr || output == nullptr || start < 0 || length <= 0) {
    return;
  }
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  auto* string_object = dynamic_cast<PseudoStringObject*>(
      PseudoObjectFromRef(reinterpret_cast<jobject>(str)));
  if (string_object == nullptr ||
      static_cast<std::size_t>(start) >= string_object->chars.size()) {
    return;
  }
  const std::size_t count =
      std::min(static_cast<std::size_t>(length),
               string_object->chars.size() - static_cast<std::size_t>(start));
  std::copy_n(string_object->chars.data() + start, count, output);
}

void CopyStringModifiedUtf8Region(jstring str, jsize start, jsize length,
                                  char* output) {
  if (str == nullptr || output == nullptr || start < 0 || length <= 0) {
    return;
  }
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  auto* string_object = dynamic_cast<PseudoStringObject*>(
      PseudoObjectFromRef(reinterpret_cast<jobject>(str)));
  if (string_object == nullptr ||
      static_cast<std::size_t>(start) >= string_object->chars.size()) {
    return;
  }
  const std::size_t count =
      std::min(static_cast<std::size_t>(length),
               string_object->chars.size() - static_cast<std::size_t>(start));
  const std::string encoded = Utf16ToModifiedUtf8(
      string_object->chars, static_cast<std::size_t>(start), count);
  std::memcpy(output, encoded.data(), encoded.size());
}

}  // namespace jnivm::internal
