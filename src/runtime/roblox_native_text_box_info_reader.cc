#include "runtime/roblox_native_text_box_info_reader.h"

#include <mutex>
#include <string>
#include <utility>

namespace mocktail {
namespace runtime {
namespace {

struct NativeTextBoxFieldIds {
  jfieldID x = nullptr;
  jfieldID y = nullptr;
  jfieldID width = nullptr;
  jfieldID height = nullptr;
  jfieldID font_size = nullptr;
  jfieldID multiline = nullptr;
  jfieldID x_alignment = nullptr;
  jfieldID y_alignment = nullptr;
  jfieldID text_color = nullptr;
  jfieldID font = nullptr;
  jfieldID text_input_type = nullptr;
  jfieldID return_key_type = nullptr;
  jfieldID manual_focus_release = nullptr;
  jfieldID text_wrapped = nullptr;
};

struct NativeTextBoxFieldCache {
  std::mutex mutex;
  JavaVM* vm = nullptr;
  jclass info_class = nullptr;
  NativeTextBoxFieldIds ids{};
};

NativeTextBoxFieldCache& FieldCache() {
  static NativeTextBoxFieldCache cache;
  return cache;
}

Status InvalidArgument(const char* message) {
  return Status::Error(StatusCode::kInvalidArgument, message);
}

Status CheckJni(JNIEnv* env, const char* operation) {
  if (env == nullptr) {
    return InvalidArgument("NativeTextBoxInfo reader requires JNIEnv");
  }
  if (env->ExceptionCheck() == JNI_FALSE) {
    return Status::Ok();
  }
  env->ExceptionClear();
  std::string message = operation != nullptr ? operation : "JNI operation";
  message += " raised an exception while reading NativeTextBoxInfo";
  return Status::Error(StatusCode::kPlatformError, std::move(message));
}

Status RequireField(JNIEnv* env, jclass info_class, const char* name,
                    const char* signature, jfieldID* field) {
  *field = env->GetFieldID(info_class, name, signature);
  Status status = CheckJni(env, name);
  if (!status.ok()) {
    return status;
  }
  if (*field == nullptr) {
    return Status::Error(
        StatusCode::kUnavailable,
        std::string("NativeTextBoxInfo field is unavailable: ") + name);
  }
  return Status::Ok();
}

Status ResolveFieldIds(JNIEnv* env, jclass info_class,
                       NativeTextBoxFieldIds* ids) {
  JavaVM* vm = nullptr;
  if (env->GetJavaVM(&vm) != JNI_OK) {
    vm = nullptr;
  }
  NativeTextBoxFieldCache& cache = FieldCache();
  if (vm != nullptr) {
    std::lock_guard<std::mutex> lock(cache.mutex);
    if (cache.vm == vm && cache.info_class == info_class &&
        cache.ids.x != nullptr) {
      *ids = cache.ids;
      return Status::Ok();
    }
  }

  NativeTextBoxFieldIds resolved{};
  Status status = RequireField(env, info_class, "x", "F", &resolved.x);
  if (status.ok()) {
    status = RequireField(env, info_class, "y", "F", &resolved.y);
  }
  if (status.ok()) {
    status = RequireField(env, info_class, "width", "F", &resolved.width);
  }
  if (status.ok()) {
    status = RequireField(env, info_class, "height", "F", &resolved.height);
  }
  if (status.ok()) {
    status = RequireField(env, info_class, "fontSize", "F",
                          &resolved.font_size);
  }
  if (status.ok()) {
    status = RequireField(env, info_class, "multiline", "Z",
                          &resolved.multiline);
  }
  if (status.ok()) {
    status = RequireField(env, info_class, "xAlignment", "I",
                          &resolved.x_alignment);
  }
  if (status.ok()) {
    status = RequireField(env, info_class, "yAlignment", "I",
                          &resolved.y_alignment);
  }
  if (status.ok()) {
    status = RequireField(env, info_class, "textColor", "I",
                          &resolved.text_color);
  }
  if (status.ok()) {
    status = RequireField(env, info_class, "font", "I", &resolved.font);
  }
  if (status.ok()) {
    status = RequireField(env, info_class, "textInputType", "I",
                          &resolved.text_input_type);
  }
  if (status.ok()) {
    status = RequireField(env, info_class, "returnKeyType", "I",
                          &resolved.return_key_type);
  }
  if (status.ok()) {
    status = RequireField(env, info_class, "manualFocusRelease", "Z",
                          &resolved.manual_focus_release);
  }
  if (status.ok()) {
    status = RequireField(env, info_class, "textWrapped", "Z",
                          &resolved.text_wrapped);
  }
  if (!status.ok()) {
    return status;
  }

  if (vm != nullptr) {
    std::lock_guard<std::mutex> lock(cache.mutex);
    cache.vm = vm;
    cache.info_class = info_class;
    cache.ids = resolved;
  }
  *ids = resolved;
  return Status::Ok();
}

Status ReadFloat(JNIEnv* env, jobject info, jfieldID field, const char* name,
                 float* value) {
  *value = env->GetFloatField(info, field);
  return CheckJni(env, name);
}

Status ReadInt(JNIEnv* env, jobject info, jfieldID field, const char* name,
               int* value) {
  *value = env->GetIntField(info, field);
  return CheckJni(env, name);
}

Status ReadBoolean(JNIEnv* env, jobject info, jfieldID field, const char* name,
                   bool* value) {
  *value = env->GetBooleanField(info, field) == JNI_TRUE;
  return CheckJni(env, name);
}

Status Snapshot(JNIEnv* env, jobject info,
                RobloxNativeTextBoxInfoSnapshot* snapshot) {
  jclass info_class = env->GetObjectClass(info);
  Status status = CheckJni(env, "GetObjectClass");
  if (!status.ok() || info_class == nullptr) {
    if (info_class != nullptr) {
      env->DeleteLocalRef(info_class);
      (void)CheckJni(env, "DeleteLocalRef(class)");
    }
    return status.ok() ? Status::Error(StatusCode::kUnavailable,
                                       "NativeTextBoxInfo class is unavailable")
                       : status;
  }

  NativeTextBoxFieldIds fields{};
  status = ResolveFieldIds(env, info_class, &fields);
  RobloxNativeTextBoxInfoSnapshot candidate;
  if (status.ok()) {
    status = ReadFloat(env, info, fields.x, "x", &candidate.x);
  }
  if (status.ok()) {
    status = ReadFloat(env, info, fields.y, "y", &candidate.y);
  }
  if (status.ok()) {
    status = ReadFloat(env, info, fields.width, "width", &candidate.width);
  }
  if (status.ok()) {
    status = ReadFloat(env, info, fields.height, "height", &candidate.height);
  }
  if (status.ok()) {
    status = ReadFloat(env, info, fields.font_size, "fontSize",
                       &candidate.font_size);
  }
  if (status.ok()) {
    status = ReadBoolean(env, info, fields.multiline, "multiline",
                         &candidate.multiline);
  }
  if (status.ok()) {
    status = ReadInt(env, info, fields.x_alignment, "xAlignment",
                     &candidate.x_alignment);
  }
  if (status.ok()) {
    status = ReadInt(env, info, fields.y_alignment, "yAlignment",
                     &candidate.y_alignment);
  }
  if (status.ok()) {
    status = ReadInt(env, info, fields.text_color, "textColor",
                     &candidate.text_color);
  }
  if (status.ok()) {
    status = ReadInt(env, info, fields.font, "font", &candidate.font);
  }
  if (status.ok()) {
    status = ReadInt(env, info, fields.text_input_type, "textInputType",
                     &candidate.text_input_type);
  }
  if (status.ok()) {
    status = ReadInt(env, info, fields.return_key_type, "returnKeyType",
                     &candidate.return_key_type);
  }
  if (status.ok()) {
    status = ReadBoolean(env, info, fields.manual_focus_release,
                         "manualFocusRelease", &candidate.manual_focus_release);
  }
  if (status.ok()) {
    status = ReadBoolean(env, info, fields.text_wrapped, "textWrapped",
                         &candidate.text_wrapped);
  }

  env->DeleteLocalRef(info_class);
  const Status delete_status = CheckJni(env, "DeleteLocalRef(class)");
  if (!status.ok()) {
    return status;
  }
  if (!delete_status.ok()) {
    return delete_status;
  }
  *snapshot = candidate;
  return Status::Ok();
}

}  // namespace

Status QueryRobloxNativeTextBoxInfo(
    JNIEnv* env, jclass native_gl_class,
    RobloxNativeGetTextBoxInfoFn native_get_text_box_info,
    RobloxNativeTextBoxInfoQueryResult* result) {
  if (env == nullptr || native_gl_class == nullptr ||
      native_get_text_box_info == nullptr || result == nullptr) {
    return InvalidArgument(
        "NativeTextBoxInfo query requires env, class, export and output");
  }
  *result = {};
  Status status = CheckJni(env, "query precondition");
  if (!status.ok()) {
    return status;
  }

  jobject local_info = native_get_text_box_info(env, native_gl_class);
  status = CheckJni(env, "nativeGetTextBoxInfo");
  if (!status.ok()) {
    if (local_info != nullptr) {
      env->DeleteLocalRef(local_info);
      (void)CheckJni(env, "DeleteLocalRef(info)");
    }
    return status;
  }
  if (local_info == nullptr) {
    return Status::Ok();
  }

  RobloxNativeTextBoxInfoSnapshot snapshot;
  status = Snapshot(env, local_info, &snapshot);
  env->DeleteLocalRef(local_info);
  const Status delete_status = CheckJni(env, "DeleteLocalRef(info)");
  if (!status.ok()) {
    return status;
  }
  if (!delete_status.ok()) {
    return delete_status;
  }
  result->available = true;
  result->info = snapshot;
  return Status::Ok();
}

}  // namespace runtime
}  // namespace mocktail
