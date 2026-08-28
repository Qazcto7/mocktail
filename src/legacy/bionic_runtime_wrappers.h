#ifndef MOCKTAIL_LEGACY_BIONIC_RUNTIME_WRAPPERS_H_
#define MOCKTAIL_LEGACY_BIONIC_RUNTIME_WRAPPERS_H_

namespace mocktail::legacy::internal {

void RegisterBionicDnsWrappers();
void RegisterBionicPathWrappers();
void RegisterBionicMemoryWrappers();

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_BIONIC_RUNTIME_WRAPPERS_H_
