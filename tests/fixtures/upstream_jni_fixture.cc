// Copyright 2026 Mocktail Project Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

#include <jni.h>

namespace {

jint NativeIncrement(JNIEnv* /*env*/, jclass /*clazz*/, jint value) {
  return value + 1;
}

}  // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
  if (vm == nullptr) {
    return JNI_ERR;
  }

  JNIEnv* env = nullptr;
  if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK ||
      env == nullptr) {
    return JNI_ERR;
  }

  jclass fixture_class = env->FindClass("com/mocktail/UpstreamFixture");
  if (fixture_class == nullptr) {
    return JNI_ERR;
  }

  const JNINativeMethod methods[] = {
      {"nativeIncrement", "(I)I", reinterpret_cast<void*>(&NativeIncrement)},
  };
  if (env->RegisterNatives(fixture_class, methods, 1) != JNI_OK) {
    return JNI_ERR;
  }

  return JNI_VERSION_1_6;
}
