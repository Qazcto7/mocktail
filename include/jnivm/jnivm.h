// Copyright 2026 Sober Test Project Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// jnivm/jnivm.h — Pseudo Java Native Interface Virtual Machine.
//
// Provides a lightweight C++ implementation of a JVM stub for use with
// Android-native shared libraries (e.g., libroblox.so) running on Linux.
// No real Java bytecode is executed; instead, all JNI calls are intercepted
// and dispatched to registered C++ callbacks.
//
// Usage:
//   auto vm = std::make_shared<jnivm::VM>();
//   auto cls = vm->RegisterClass("android/content/Context");
//   cls->RegisterMethod("getSystemService",
//   "(Ljava/lang/String;)Ljava/lang/Object;",
//                       [](JNIEnv*, jobject, ...) { return nullptr; });

#ifndef SOBER_TEST_JNIVM_JNIVM_H_
#define SOBER_TEST_JNIVM_JNIVM_H_

#include <jni.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace jnivm {

// Forward declarations

class VM;
class Class;

// Object — base type for all pseudo-Java objects managed by the pseudo-JVM.
// Analogous to java.lang.Object in the real JVM.

class Object {
public:
  explicit Object(std::shared_ptr<Class> klass) : klass_(std::move(klass)) {}
  virtual ~Object() = default;

  // Returns the pseudo-class descriptor of this object.
  std::shared_ptr<Class> GetClass() const { return klass_; }

private:
  std::shared_ptr<Class> klass_;
};

// MethodCallback — signature for registered JNI method stubs.
// The callback receives the raw JNIEnv pointer and the receiver jobject.

using MethodCallback = std::function<void(JNIEnv *, jobject)>;

// Resolved Roblox account identity supplied by the host runtime. This
// intentionally contains no cookie or other authentication credential.
struct RobloxAuthIdentity {
  int64_t user_id = -1;
  std::string username;
  std::string display_name;
};

// Host device capabilities exposed through the pseudo Android framework.
// The guest ABI remains Android, while the default profile // describes a Linux desktop with physical mouse and keyboard input.
struct PlatformIdentity {
  bool touch_enabled = false;
  bool mouse_enabled = true;
  bool keyboard_enabled = true;
  bool pc_hardware = true;
  std::string platform_name = "Linux";
  std::string device_name = "Mocktail Headless";
  std::string manufacturer = "Mocktail";
  std::string model = "Mocktail Headless";
  std::string brand = "Mocktail";
  std::string device_code = "linux-x86_64";
  std::string device_sku = "mocktail-x86_64";
  std::string soc_model = "x86_64";
};

struct RobloxCredentialView {
  const char *data = nullptr;
  std::size_t size = 0;
};

using RobloxCredentialProvider = RobloxCredentialView (*)(const void *context);

// Creates a Configuration object consistent with the VM's immutable platform
// identity snapshot. This is the replacement for legacy construction of
// contradictory Android keyboard/touch fields.
jobject CreateAndroidConfiguration(JNIEnv *env);

// Narrow write-only boundary for credentials produced by Roblox after the
// native runtime has started. A successfully persisted value supersedes the
// bound provider for the remainder of the current VM lifetime so native sign-in
// can become authoritative without reopening an untrusted credential source.
struct RobloxCredentialSinkCallbacks {
  bool (*store)(void *context, const char *data, std::size_t size) = nullptr;
};

// Narrow host callback boundary for org/fmod/AudioDevice. The pseudo-JVM owns
// only an opaque shared context and never depends on the SDL audio runtime.
// Each Java receiver is passed as a stable identity so the host can keep
// independent device lifecycles without retaining a JNI local reference.
struct FmodAudioDeviceCallbacks {
  bool (*init)(void *context, const void *identity, int channels,
               int sample_rate_hz, int block_size_frames,
               int block_count) = nullptr;
  bool (*write)(void *context, const void *identity, const std::uint8_t *data,
                std::size_t size) = nullptr;
  bool (*close)(void *context, const void *identity) = nullptr;
  void (*shutdown)(void *context) = nullptr;
};

// Narrow host callback boundary for the activity.setWindowFlags(II)V contract.
// Production LuaApp retains its activity through the android.app.Activity
// interface, while GameActivity startup uses the concrete subclass. Guest JNI
// threads only publish Android flags; the platform callback must marshal any
// SDL work onto the SDL main thread.
struct AndroidWindowCallbacks {
  bool (*set_flags)(void *context, int flags, int mask) = nullptr;
};

// Immutable snapshot of the Android NativeTextBoxInfo payload supplied by
// Roblox when a native text field receives focus.
struct RobloxTextBoxInfo {
  float x = 0.0f;
  float y = 0.0f;
  float width = 0.0f;
  float height = 0.0f;
  float font_size = 0.0f;
  bool multiline = false;
  int x_alignment = 0;
  int y_alignment = 0;
  int text_color = 0;
  int font = 0;
  int text_input_type = 0;
  int return_key_type = 0;
  bool manual_focus_release = false;
  bool text_wrapped = false;
};

struct RobloxTextInputShowRequest {
  std::int64_t text_box = 0;
  bool show_native_input = false;
  std::string text;
  RobloxTextBoxInfo info;
};

// Narrow callback boundary for the Roblox native text-input callbacks. The
// pseudo-JVM snapshots all JNI-owned arguments before entering this boundary.
struct RobloxTextInputCallbacks {
  void (*show)(void *context,
               const RobloxTextInputShowRequest &request) = nullptr;
  void (*hide)(void *context) = nullptr;
  void (*replace_text)(void *context, const std::string &text) = nullptr;
  void (*properties_changed)(void *context) = nullptr;
  void (*shutdown)(void *context) = nullptr;
};

// Narrow boundary for a native MessageBus RawCallback object. The VM
// retains context while a callback is in flight and dispatches only the exact
// run(Ljava/lang/String;)V method on the exact created receiver.
struct MessageBusRawCallbacks {
  void (*run)(void *context, JNIEnv *env, jstring message) = nullptr;
};

struct MessageBusRequestHandlerCallbacks {
  std::string (*run)(void *context, JNIEnv *env, jstring message) = nullptr;
};

// Narrow boundary for the current APK's legacy BrowserService transport.
// Dispatch accepts only Callback.onItemSet(Ljava/lang/String;)V on the exact
// pseudo receiver created by CreateMemStorageCallback.
struct MemStorageCallbackCallbacks {
  void (*on_item_set)(void *context, JNIEnv *env, jstring value) = nullptr;
};

// Narrow boundary for the exact APK callbacks that update host web
// state: NativeGLJavaInterface notifications, web activities, cookie sync,
// and JNICookieProtocol.OnSetCookieHandler. The VM retains the shared callback
// context while a callback is in flight; consumers must copy JNI strings
// before returning.
struct RobloxDataModelNotificationCallbacks {
  void (*on_notification)(void *context, JNIEnv *env, jstring type,
                          jstring data) = nullptr;
  void (*on_app_bridge_notification)(void* context, JNIEnv* env, jstring type,
                                     jstring data) = nullptr;
  void (*on_native_overlay)(void* context, JNIEnv* env, jstring title,
                            jstring url) = nullptr;
  void (*on_open_web_activity)(void* context, JNIEnv* env, jstring url,
                               jstring title) = nullptr;
  void (*on_sync_cookies)(void* context, JNIEnv* env, jstring cookie) = nullptr;
  void (*on_set_cookie)(void* context, JNIEnv* env, jstring cookie,
                        jstring url) = nullptr;
};

// Narrow boundary for the exact NativeHelper lifecycle notification
// emitted when Roblox returns from an experience to LuaApp.
struct RobloxExperienceLifecycleCallbacks {
  void (*on_lua_app_did_return)(void *context) = nullptr;
};

// Class — represents a pseudo Java class registered in the pseudo-JVM.
// Stores the class name (JNI descriptor format) and a map of method stubs.

class Class {
public:
  explicit Class(std::string name) : name_(std::move(name)) {}

  // Returns the JNI-style class descriptor, e.g. "android/content/Context".
  const std::string &GetName() const { return name_; }

  // Registers a JNI method stub.
  //
  // Args:
  //   method_name: Simple method name (e.g. "getSystemService").
  //   signature:   JNI type descriptor (e.g. "(Ljava/lang/String;)V").
  //   callback:    C++ lambda invoked when the method is called via JNI.
  void RegisterMethod(const std::string &method_name,
                      const std::string &signature, MethodCallback callback);

  // Looks up a method stub by name and signature.
  // Returns nullptr if not found.
  const MethodCallback *FindMethod(const std::string &method_name,
                                   const std::string &signature) const;

  // Returns all registered methods (name → callback).
  const std::unordered_map<std::string, MethodCallback> &GetMethods() const {
    return methods_;
  }

private:
  std::string name_;

  // Key format: "methodName:descriptor"
  std::unordered_map<std::string, MethodCallback> methods_;
};

// VM — the top-level pseudo Java Virtual Machine.
//
// Owns a registry of pseudo-classes and exposes a JavaVM* compatible
// pointer for passing to JNI_OnLoad in the loaded shared library.

class VM {
public:
  VM();
  ~VM();

  // Disallow copy and assign.
  VM(const VM &) = delete;
  VM &operator=(const VM &) = delete;

  // Registers a new pseudo-class by its JNI descriptor.
  // Repeated registration returns the existing instance.
  //
  // Args:
  //   class_name: JNI-style descriptor, e.g.
  //   "com/roblox/client/RobloxActivity".
  //
  // Returns:
  //   Shared pointer to the registered (or pre-existing) Class object.
  std::shared_ptr<Class> RegisterClass(const std::string &class_name);

  // Finds a previously registered class.
  // Returns nullptr if the class has not been registered.
  std::shared_ptr<Class> FindClass(const std::string &class_name) const;

  // Returns the raw JavaVM pointer compatible with JNI_OnLoad signature.
  JavaVM *GetJavaVM() { return java_vm_; }

  // Resolves the process pseudo-VM that owns an exact JavaVM pointer. Returns
  // null for foreign VMs and after the owner is destroyed.
  static VM *FromJavaVM(JavaVM *java_vm);

  // Returns the attached JNIEnv pointer for the current host thread.
  JNIEnv *GetJNIEnv();

  // Returns the number of registered classes.
  std::size_t GetClassCount() const { return class_registry_.size(); }

  // Replaces the resolved account identity with an independent copy. Invalid
  // (non-positive) identities are normalized to the unresolved state.
  void SetRobloxAuthIdentity(const RobloxAuthIdentity &identity);

  // Returns the VM to its unresolved account state.
  void ClearRobloxAuthIdentity();

  // Returns an immutable-by-value snapshot safe for use by JNI callbacks on
  // another thread.
  RobloxAuthIdentity GetRobloxAuthIdentitySnapshot() const;

  void SetPlatformIdentity(const PlatformIdentity &identity);
  PlatformIdentity GetPlatformIdentitySnapshot() const;

  // Installs a non-owning production credential provider. A configured
  // provider returning an empty view blocks legacy env/disk
  // fallback for guest sessions. The provider owner must outlive all JNI
  // calls and clear the provider only after native workers have stopped.
  void SetRobloxCredentialProvider(const void *context,
                                   RobloxCredentialProvider provider);
  void ClearRobloxCredentialProvider();

  // Returns true when the authoritative provider is configured, including an
  // explicitly empty guest credential. A credential accepted by the sink is
  // retained privately and returned instead until the provider is cleared.
  bool CopyRobloxCredentialFromProvider(std::string *credential) const;

  void SetRobloxCredentialSink(std::shared_ptr<void> context,
                               const RobloxCredentialSinkCallbacks &callbacks);
  void ClearRobloxCredentialSink();
  bool DispatchRobloxCredential(const char *data, std::size_t size);

  // Installs an org/fmod/AudioDevice backend. The VM retains context for
  // every in-flight callback and calls shutdown when the binding is cleared or
  // the VM is destroyed. Replacing or clearing a binding is only safe after
  // guest JNI worker threads have stopped.
  void SetFmodAudioDeviceCallbacks(std::shared_ptr<void> context,
                                   const FmodAudioDeviceCallbacks &callbacks);
  void ClearFmodAudioDeviceCallbacks();

  // Internal dispatch entry points used by the JNI function table. They are
  // public because JNI requires captureless C-compatible callbacks.
  bool DispatchFmodAudioDeviceInit(const void *identity, int channels,
                                   int sample_rate_hz, int block_size_frames,
                                   int block_count);
  bool DispatchFmodAudioDeviceWrite(const void *identity,
                                    const std::uint8_t *data, std::size_t size);
  bool DispatchFmodAudioDeviceClose(const void *identity);

  void SetAndroidWindowCallbacks(std::shared_ptr<void> context,
                                 const AndroidWindowCallbacks &callbacks);
  void ClearAndroidWindowCallbacks();
  bool DispatchAndroidWindowFlags(int flags, int mask);

  void SetRobloxTextInputCallbacks(std::shared_ptr<void> context,
                                   const RobloxTextInputCallbacks &callbacks);
  void ClearRobloxTextInputCallbacks();
  bool DispatchRobloxTextInputShow(const RobloxTextInputShowRequest &request);
  bool DispatchRobloxTextInputHide();
  bool DispatchRobloxTextInputReplaceText(const std::string &text);
  bool DispatchRobloxTextInputPropertiesChanged();

  // Creates a pseudo com.roblox.universalapp.messagebus.RawCallback receiver
  // backed by a host callback. Clear removes future dispatch while an
  // already-running call keeps its shared context alive until return.
  jobject CreateMessageBusRawCallback(std::shared_ptr<void> context,
                                      const MessageBusRawCallbacks &callbacks);
  void ClearMessageBusRawCallback(jobject callback);
  bool DispatchMessageBusRawCallback(jobject callback, JNIEnv *env,
                                     jstring message);
  jobject CreateMessageBusRequestHandler(
      std::shared_ptr<void> context,
      const MessageBusRequestHandlerCallbacks &callbacks);
  void ClearMessageBusRequestHandler(jobject handler);
  jstring DispatchMessageBusRequestHandler(jobject handler, JNIEnv *env,
                                           jstring message);

  // Creates the exact com.roblox.engine.jni.memstorage.Callback receiver used
  // by MemStorage.bind. Clear prevents future dispatch while an in-flight call
  // retains its shared context until the callback returns.
  jobject CreateMemStorageCallback(
      std::shared_ptr<void> context,
      const MemStorageCallbackCallbacks& callbacks);
  void ClearMemStorageCallback(jobject callback);
  bool DispatchMemStorageCallback(jobject callback, JNIEnv *env, jstring value);

  // Installs the platform web callbacks reached through NativeGLJavaInterface,
  // MainGameActivity, and JNICookieProtocol. Clear prevents future dispatch
  // while an in-flight call retains its shared context until return.
  void SetRobloxDataModelNotificationCallbacks(
      std::shared_ptr<void> context,
      const RobloxDataModelNotificationCallbacks &callbacks);
  void ClearRobloxDataModelNotificationCallbacks();
  bool DispatchRobloxDataModelNotification(JNIEnv *env, jstring type,
                                           jstring data);
  bool DispatchRobloxAppBridgeNotification(JNIEnv* env, jstring type,
                                           jstring data);
  bool DispatchRobloxNativeOverlay(JNIEnv* env, jstring title, jstring url);
  bool DispatchRobloxOpenWebActivity(JNIEnv* env, jstring url, jstring title);
  bool DispatchRobloxCookieSync(JNIEnv* env, jstring cookie);
  bool DispatchRobloxCookieSet(JNIEnv* env, jobjectArray cookies, jstring url);

  // Installs the callback used by the exact NativeHelper
  // gameActivity_onLuaAppDidReturn()V and ASMA/V2 NativeGLJavaInterface
  // gameDidLeave()V contracts. Dispatch snapshots the shared binding so Clear
  // cannot destroy context while a call is in flight.
  void SetRobloxExperienceLifecycleCallbacks(
      std::shared_ptr<void> context,
      const RobloxExperienceLifecycleCallbacks &callbacks);
  void ClearRobloxExperienceLifecycleCallbacks();
  bool DispatchRobloxExperienceLuaAppDidReturn();

  // Restores env->functions to &native_interface_ in case libroblox replaced
  // it.
  void RestoreFunctions();

private:
  // Internal JNI function tables populated with stub implementations.
  JNIInvokeInterface_ invoke_interface_ = {};
  JavaVM java_vm_storage_ = {};
  JavaVM *java_vm_ = nullptr;

  JNINativeInterface_ native_interface_ = {};
  JNIEnv jni_env_storage_ = {};
  JNIEnv *jni_env_ = nullptr;

  // Registry of pseudo-classes indexed by their JNI descriptor.
  std::unordered_map<std::string, std::shared_ptr<Class>> class_registry_;

  mutable std::mutex roblox_auth_identity_mutex_;
  RobloxAuthIdentity roblox_auth_identity_;

  mutable std::mutex platform_identity_mutex_;
  PlatformIdentity platform_identity_;

  mutable std::mutex roblox_credential_provider_mutex_;
  const void *roblox_credential_provider_context_ = nullptr;
  RobloxCredentialProvider roblox_credential_provider_ = nullptr;
  std::string roblox_credential_override_;

  struct RobloxCredentialSinkBinding {
    std::shared_ptr<void> context;
    RobloxCredentialSinkCallbacks callbacks;
  };
  mutable std::mutex roblox_credential_sink_mutex_;
  RobloxCredentialSinkBinding roblox_credential_sink_binding_;

  struct FmodAudioDeviceBinding {
    std::shared_ptr<void> context;
    FmodAudioDeviceCallbacks callbacks;
  };
  mutable std::mutex fmod_audio_device_mutex_;
  FmodAudioDeviceBinding fmod_audio_device_binding_;

  struct AndroidWindowBinding {
    std::shared_ptr<void> context;
    AndroidWindowCallbacks callbacks;
  };
  mutable std::mutex android_window_mutex_;
  AndroidWindowBinding android_window_binding_;

  struct RobloxTextInputBinding;
  mutable std::mutex roblox_text_input_mutex_;
  std::shared_ptr<RobloxTextInputBinding> roblox_text_input_binding_;

  struct MessageBusRawBinding {
    std::shared_ptr<void> context;
    MessageBusRawCallbacks callbacks;
  };
  mutable std::mutex message_bus_raw_mutex_;
  std::unordered_map<jobject, std::shared_ptr<MessageBusRawBinding>>
      message_bus_raw_bindings_;

  struct MessageBusRequestHandlerBinding {
    std::shared_ptr<void> context;
    MessageBusRequestHandlerCallbacks callbacks;
  };
  mutable std::mutex message_bus_request_handler_mutex_;
  std::unordered_map<jobject, std::shared_ptr<MessageBusRequestHandlerBinding>>
      message_bus_request_handler_bindings_;

  struct MemStorageCallbackBinding {
    std::shared_ptr<void> context;
    MemStorageCallbackCallbacks callbacks;
  };
  mutable std::mutex mem_storage_callback_mutex_;
  std::unordered_map<jobject, std::shared_ptr<MemStorageCallbackBinding>>
      mem_storage_callback_bindings_;

  struct RobloxDataModelNotificationBinding {
    std::shared_ptr<void> context;
    RobloxDataModelNotificationCallbacks callbacks;
  };
  mutable std::mutex roblox_data_model_notification_mutex_;
  std::shared_ptr<RobloxDataModelNotificationBinding>
      roblox_data_model_notification_binding_;

  struct RobloxExperienceLifecycleBinding {
    std::shared_ptr<void> context;
    RobloxExperienceLifecycleCallbacks callbacks;
  };
  mutable std::mutex roblox_experience_lifecycle_mutex_;
  std::shared_ptr<RobloxExperienceLifecycleBinding>
      roblox_experience_lifecycle_binding_;

  // Initialises the JNIInvokeInterface_ and JNINativeInterface_ function tables
  // with stub implementations that forward calls to this VM instance.
  void InitJNIFunctionTables();
};

} // namespace jnivm

#endif // SOBER_TEST_JNIVM_JNIVM_H_
