#ifndef MOCKTAIL_JNIVM_JNI_REFERENCES_H_
#define MOCKTAIL_JNIVM_JNI_REFERENCES_H_

#include <cstdint>
#include <string_view>
#include <unordered_set>

#include "jnivm/jnivm.h"

namespace jnivm::internal {

// Shared by reference ownership and object/field access. Callers retaining a
// raw PseudoJavaObject pointer must keep its JNI reference alive.
extern std::recursive_mutex g_jni_state_mutex;

struct PseudoArray {
  ~PseudoArray();
  uint32_t ref_count = 1;
  std::vector<jbyte> bytes;
  std::vector<jfloat> floats;
  std::vector<jobject> objects;
};

struct PseudoFieldEntry {
  enum class Kind : uint8_t {
    kObject,
    kInt,
    kLong,
    kFloat,
    kBoolean,
  };
  const char* name = nullptr;
  Kind kind = Kind::kObject;
  union {
    jobject object_val;
    jint int_val;
    jlong long_val;
    jfloat float_val;
    jboolean boolean_val;
  } value{};
};

struct PseudoObjectFields {
  std::vector<PseudoFieldEntry> entries;
};

struct PseudoJavaObject : Object {
  explicit PseudoJavaObject(std::shared_ptr<Class> cls, bool is_string = false)
      : Object(std::move(cls)), is_string_(is_string) {}

  ~PseudoJavaObject() override;

  bool IsString() const { return is_string_; }
  const PseudoObjectFields* Fields() const { return fields_.get(); }
  PseudoObjectFields* MutableFields() {
    if (!fields_) {
      fields_ = std::make_unique<PseudoObjectFields>();
    }
    return fields_.get();
  }

 private:
  std::unique_ptr<PseudoObjectFields> fields_;
  bool is_string_ = false;
};

bool TraceEnabled();
void RegisterLocalRef(jobject obj);
void UnregisterLocalRef(jobject obj);
void RetainJniReference(jobject obj);
void ReleaseJniReference(jobject obj);
void ReleaseAllLocalJniFrames();
void RegisterDirectBufferCapacity(jobject buffer, jlong capacity);
jlong DirectBufferCapacityValue(jobject buffer);
jobject NewLocalJniReference(jobject obj);
void DeleteLocalJniReference(jobject obj);
void PushLocalJniFrame();
jobject PopLocalJniFrame(jobject result);
std::shared_ptr<Class> FallbackClassForName(const std::string& name);
std::shared_ptr<Class> ClassFromJClass(jclass clazz);
jclass StoreClass(std::shared_ptr<Class> cls);
jobject StoreObject(std::unique_ptr<Object> object);
PseudoJavaObject* PseudoObjectFromRef(jobject obj);
bool IsSegmentHandle(jobject obj);
jobject MakeObjectForClass(const std::string& name);
jobject MakeObject(jclass clazz);
jobject SingletonObject(const std::string& name);
std::string_view ObjectClassName(jobject obj);
PseudoArray* ArrayFromRef(jarray array);
jbyteArray MakeByteArray(jsize len);
jfloatArray MakeFloatArray(jsize len);
jobjectArray MakeObjectArray(jsize len, jobject init);

}  // namespace jnivm::internal
#endif
