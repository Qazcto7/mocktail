#include "jni_fields.h"

#include <cstring>

#include "jni_references.h"

namespace jnivm::internal {
namespace {
std::unordered_set<std::string> g_field_names;
std::unordered_map<std::string, jobject> g_static_object_fields;

const char* InternFieldNameLocked(const char* name) {
  const auto stored = g_field_names.emplace(name).first;
  // unordered_set preserves references to its elements across rehashes.
  return stored->c_str();
}

PseudoFieldEntry* FindFieldEntry(PseudoObjectFields* fields,
                                 const char* field_name,
                                 PseudoFieldEntry::Kind kind) {
  if (fields == nullptr || field_name == nullptr) {
    return nullptr;
  }
  for (auto& entry : fields->entries) {
    if (entry.kind == kind &&
        (entry.name == field_name || std::strcmp(entry.name, field_name) == 0)) {
      return &entry;
    }
  }
  return nullptr;
}

const PseudoFieldEntry* FindFieldEntry(const PseudoObjectFields* fields,
                                       const char* field_name,
                                       PseudoFieldEntry::Kind kind) {
  if (fields == nullptr || field_name == nullptr) {
    return nullptr;
  }
  for (const auto& entry : fields->entries) {
    if (entry.kind == kind &&
        (entry.name == field_name || std::strcmp(entry.name, field_name) == 0)) {
      return &entry;
    }
  }
  return nullptr;
}

void UpsertPrimitiveFieldLocked(jobject obj, const char* field_name,
                                PseudoFieldEntry::Kind kind,
                                PseudoFieldEntry entry) {
  PseudoJavaObject* pseudo_object = PseudoObjectFromRef(obj);
  if (pseudo_object == nullptr || field_name == nullptr) {
    return;
  }
  PseudoObjectFields* fields = pseudo_object->MutableFields();
  if (auto* existing = FindFieldEntry(fields, field_name, kind);
      existing != nullptr) {
    existing->value = entry.value;
    return;
  }
  entry.name = InternFieldNameLocked(field_name);
  entry.kind = kind;
  fields->entries.push_back(entry);
}
}  // namespace

jfieldID StoreFieldId(const char* name) {
  if (name == nullptr) return nullptr;
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  return reinterpret_cast<jfieldID>(const_cast<char*>(InternFieldNameLocked(name)));
}

void SetStaticObjectFieldRaw(const char* name, jobject value) {
  if (name == nullptr) return;
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  RetainJniReference(value);
  auto& field = g_static_object_fields[name];
  const jobject previous = field;
  field = value;
  ReleaseJniReference(previous);
}

jobject StaticObjectFieldValue(const char* name) {
  if (name == nullptr) return nullptr;
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  const auto found = g_static_object_fields.find(name);
  return found == g_static_object_fields.end()
             ? nullptr
             : NewLocalJniReference(found->second);
}

void SetObjectFieldRaw(jobject obj, const char* field_name, jobject value) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  PseudoJavaObject* pseudo_object = PseudoObjectFromRef(obj);
  if (pseudo_object && field_name) {
    RetainJniReference(value);
    PseudoObjectFields* fields = pseudo_object->MutableFields();
    if (auto* existing = FindFieldEntry(fields, field_name,
                                        PseudoFieldEntry::Kind::kObject);
        existing != nullptr) {
      jobject prev = existing->value.object_val;
      existing->value.object_val = value;
      if (prev != nullptr) {
        ReleaseJniReference(prev);
      }
      return;
    }
    PseudoFieldEntry entry;
    entry.name = InternFieldNameLocked(field_name);
    entry.kind = PseudoFieldEntry::Kind::kObject;
    entry.value.object_val = value;
    fields->entries.push_back(entry);
  }
}

void SetIntFieldRaw(jobject obj, const char* field_name, jint value) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  PseudoFieldEntry entry;
  entry.value.int_val = value;
  UpsertPrimitiveFieldLocked(obj, field_name, PseudoFieldEntry::Kind::kInt,
                             entry);
}

void SetLongFieldRaw(jobject obj, const char* field_name, jlong value) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  PseudoFieldEntry entry;
  entry.value.long_val = value;
  UpsertPrimitiveFieldLocked(obj, field_name, PseudoFieldEntry::Kind::kLong,
                             entry);
}

void SetFloatFieldRaw(jobject obj, const char* field_name, jfloat value) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  PseudoFieldEntry entry;
  entry.value.float_val = value;
  UpsertPrimitiveFieldLocked(obj, field_name, PseudoFieldEntry::Kind::kFloat,
                             entry);
}

void SetBooleanFieldRaw(jobject obj, const char* field_name, jboolean value) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  PseudoFieldEntry entry;
  entry.value.boolean_val = value;
  UpsertPrimitiveFieldLocked(obj, field_name, PseudoFieldEntry::Kind::kBoolean,
                             entry);
}

jobject ObjectFieldValue(jobject obj, const char* field_name) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  auto* pseudo_object = PseudoObjectFromRef(obj);
  if (!pseudo_object || !field_name) {
    return nullptr;
  }
  const auto* entry = FindFieldEntry(pseudo_object->Fields(), field_name,
                                     PseudoFieldEntry::Kind::kObject);
  return entry == nullptr ? nullptr
                          : NewLocalJniReference(entry->value.object_val);
}

jint IntFieldValue(jobject obj, const char* field_name) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  auto* pseudo_object = PseudoObjectFromRef(obj);
  if (!pseudo_object || !field_name) {
    return 0;
  }
  const auto* entry = FindFieldEntry(pseudo_object->Fields(), field_name,
                                     PseudoFieldEntry::Kind::kInt);
  return entry == nullptr ? 0 : entry->value.int_val;
}

jboolean BooleanFieldValue(jobject obj, const char* field_name) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  auto* pseudo_object = PseudoObjectFromRef(obj);
  if (!pseudo_object || !field_name) {
    return JNI_FALSE;
  }
  const auto* entry = FindFieldEntry(pseudo_object->Fields(), field_name,
                                     PseudoFieldEntry::Kind::kBoolean);
  return entry == nullptr ? JNI_FALSE : entry->value.boolean_val;
}

jlong LongFieldValue(jobject obj, const char* field_name) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  auto* pseudo_object = PseudoObjectFromRef(obj);
  if (!pseudo_object || !field_name) {
    return 0;
  }
  const auto* entry = FindFieldEntry(pseudo_object->Fields(), field_name,
                                     PseudoFieldEntry::Kind::kLong);
  return entry == nullptr ? 0 : entry->value.long_val;
}

jfloat FloatFieldValue(jobject obj, const char* field_name) {
  std::lock_guard<std::recursive_mutex> lock(g_jni_state_mutex);
  auto* pseudo_object = PseudoObjectFromRef(obj);
  if (!pseudo_object || !field_name) {
    return 0.0f;
  }
  const auto* entry = FindFieldEntry(pseudo_object->Fields(), field_name,
                                     PseudoFieldEntry::Kind::kFloat);
  return entry == nullptr ? 0.0f : entry->value.float_val;
}

}  // namespace jnivm::internal
