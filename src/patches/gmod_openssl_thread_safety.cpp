#include "patches/patch_api.h"

#include <cstdlib>
#include <dlfcn.h>
#include <pthread.h>

// GMod join crash: OpenSSL 1.0.0 thread-safety (LINUX ONLY).
//
// The Steam runtime ships OpenSSL 1.0.0, which REQUIRES the app to install a
// locking callback (CRYPTO_set_locking_callback) before doing crypto from
// multiple threads -- otherwise concurrent operations corrupt OpenSSL's global
// state. GMod/the runtime never installs one, so when joining a server triggers
// concurrent certificate verification on several worker threads (workshop /
// HTTPS / master-server certs), the race corrupts crypto state and crashes:
//   X509_verify_cert -> X509_get_pubkey -> RSA_new_method -> NULL deref SIGSEGV.
//
// Verified live (GDB): CRYPTO_get_locking_callback() == NULL, and two worker
// threads were faulting in RSA_new_method at the same time -- the textbook
// missing-locking-callback symptom.
//
// Fix is the textbook one: allocate CRYPTO_num_locks() mutexes and install the
// standard locking + thread-id callbacks. This serializes OpenSSL global-state
// access and removes the race. Filling in setup the app should have done; safe
// and process-global.
namespace patches::gmod {
namespace {

using num_locks_fn = int (*)();
using set_locking_fn = void (*)(void (*)(int, int, const char*, int));
using set_id_fn = void (*)(unsigned long (*)());
using get_locking_fn = void* (*)();

pthread_mutex_t* g_locks = nullptr;
int g_lock_count = 0;
bool g_installed = false;

constexpr int k_crypto_lock = 0x01;  // CRYPTO_LOCK

void locking_callback(int mode, int n, const char* /*file*/, int /*line*/) {
    if (n < 0 || n >= g_lock_count) {
        return;
    }
    // Proof-of-life: log the first time OpenSSL actually invokes our callback.
    LOG_ONCE("patch[gmod_openssl_thread_safety]: locking_callback FIRED (lib is "
             "using our locks; lock=%d tid=%lu)", n,
             static_cast<unsigned long>(pthread_self()));
    if (mode & k_crypto_lock) {
        pthread_mutex_lock(&g_locks[n]);
    } else {
        pthread_mutex_unlock(&g_locks[n]);
    }
}

unsigned long id_callback() {
    return static_cast<unsigned long>(pthread_self());
}

bool install() {
    if (g_installed) {
        return true;
    }
    void* crypto = memory::get_module_handle("libcrypto.so.1.0.0");
    if (!crypto) {
        return false;  // not loaded yet -> retry next reconcile
    }
    auto num_locks = reinterpret_cast<num_locks_fn>(dlsym(crypto, "CRYPTO_num_locks"));
    auto set_locking = reinterpret_cast<set_locking_fn>(dlsym(crypto, "CRYPTO_set_locking_callback"));
    auto get_locking = reinterpret_cast<get_locking_fn>(dlsym(crypto, "CRYPTO_get_locking_callback"));
    auto set_id = reinterpret_cast<set_id_fn>(dlsym(crypto, "CRYPTO_set_id_callback"));
    if (!num_locks || !set_locking || !get_locking || !set_id) {
        return false;
    }
    // Respect an existing callback -- never stomp a working setup.
    if (get_locking() != nullptr) {
        g_installed = true;
        return true;
    }
    const int n = num_locks();
    if (n <= 0 || n > 4096) {
        return false;
    }
    g_locks = static_cast<pthread_mutex_t*>(std::calloc(static_cast<std::size_t>(n), sizeof(pthread_mutex_t)));
    if (!g_locks) {
        return false;
    }
    for (int i = 0; i < n; ++i) {
        pthread_mutex_init(&g_locks[i], nullptr);
    }
    g_lock_count = n;
    set_id(&id_callback);
    set_locking(&locking_callback);  // last: callbacks are usable the moment this is set
    g_installed = true;
    LOG_ONCE("patch[gmod_openssl_thread_safety]: installed OpenSSL 1.0.0 locking callbacks (%d locks)", n);
    return true;
}

void remove() {
    // Intentionally permanent: clearing the callback mid-process re-exposes the
    // race, and freeing the mutexes while crypto may be running is unsafe.
}

const game_patch g_patch{
    "gmod_openssl_thread_safety",
    &install,
    &remove,
};

struct auto_register {
    auto_register() { patches::register_patch(&g_patch); }
} g_auto_register;

} // namespace
} // namespace patches::gmod
