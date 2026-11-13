#include <gtest/gtest.h>
#include <vulkan/vulkan.h>

#include <dlfcn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>

namespace {

void ExpectAdapterDispatch(bool host_first) {
  // Isolate the ELF global symbol scope for each load order. A dependency
  // such as libplacebo can load the system Vulkan library before our adapter.
  const pid_t child = fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    void* host = nullptr;
    if (host_first) {
      host = dlopen(MOCKTAIL_VULKAN_HOST_FIXTURE, RTLD_NOW | RTLD_GLOBAL);
      if (host == nullptr) std::_Exit(10);
    }
    void* adapter = dlopen(MOCKTAIL_VULKAN_ADAPTER, RTLD_NOW | RTLD_LOCAL);
    if (adapter == nullptr) {
      std::fprintf(stderr, "Vulkan adapter load failed: %s\n", dlerror());
      std::_Exit(11);
    }
    if (!host_first) {
      host = dlopen(MOCKTAIL_VULKAN_HOST_FIXTURE, RTLD_NOW | RTLD_GLOBAL);
      if (host == nullptr) std::_Exit(12);
    }
    const auto get = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        dlsym(adapter, "vkGetInstanceProcAddr"));
    if (get == nullptr) std::_Exit(13);

    for (const char* name : {"vkCreateInstance", "vkGetInstanceProcAddr",
                             "vkEnumerateInstanceExtensionProperties",
                             "vkEnumerateInstanceLayerProperties"}) {
      const auto expected =
          reinterpret_cast<PFN_vkVoidFunction>(dlsym(adapter, name));
      const auto host_function =
          reinterpret_cast<PFN_vkVoidFunction>(dlsym(host, name));
      if (expected == nullptr || expected == host_function ||
          get(VK_NULL_HANDLE, name) != expected) {
        std::fprintf(stderr, "Vulkan adapter dispatch escaped to host: %s\n",
                     name);
        std::_Exit(14);
      }
    }
    std::_Exit(0);
  }
  int status = 0;
  ASSERT_EQ(waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(VulkanLoaderAdapterTest, KeepsOwnDispatchWhenHostLoadsFirst) {
  ExpectAdapterDispatch(true);
}

TEST(VulkanLoaderAdapterTest, KeepsOwnDispatchWhenAdapterLoadsFirst) {
  ExpectAdapterDispatch(false);
}

TEST(VulkanLoaderAdapterTest, HandlesNullDestroyAndNullCreateArraysSafely) {
  const pid_t child = fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    void* adapter = dlopen(MOCKTAIL_VULKAN_ADAPTER, RTLD_NOW | RTLD_LOCAL);
    if (adapter == nullptr) {
      std::_Exit(20);
    }
    const auto destroy_instance =
        reinterpret_cast<PFN_vkDestroyInstance>(
            dlsym(adapter, "vkDestroyInstance"));
    const auto destroy_device =
        reinterpret_cast<PFN_vkDestroyDevice>(dlsym(adapter, "vkDestroyDevice"));
    const auto create_device =
        reinterpret_cast<PFN_vkCreateDevice>(dlsym(adapter, "vkCreateDevice"));
    const auto surface_caps =
        reinterpret_cast<PFN_vkGetPhysicalDeviceSurfaceCapabilitiesKHR>(
            dlsym(adapter, "vkGetPhysicalDeviceSurfaceCapabilitiesKHR"));
    if (destroy_instance == nullptr || destroy_device == nullptr ||
        create_device == nullptr || surface_caps == nullptr) {
      std::_Exit(21);
    }
    destroy_instance(VK_NULL_HANDLE, nullptr);
    destroy_device(VK_NULL_HANDLE, nullptr);

    VkDeviceCreateInfo dev_info{};
    dev_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dev_info.queueCreateInfoCount = 1;
    dev_info.pQueueCreateInfos = nullptr;
    VkDevice dev = VK_NULL_HANDLE;
    if (create_device(VK_NULL_HANDLE, &dev_info, nullptr, &dev) !=
        VK_ERROR_INITIALIZATION_FAILED) {
      std::_Exit(22);
    }
    if (surface_caps(VK_NULL_HANDLE, VK_NULL_HANDLE, nullptr) !=
        VK_ERROR_INITIALIZATION_FAILED) {
      std::_Exit(23);
    }
    std::_Exit(0);
  }
  int status = 0;
  ASSERT_EQ(waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

}  // namespace
