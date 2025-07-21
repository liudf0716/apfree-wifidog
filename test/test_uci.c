#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "wd_util.h"
#include "debug.h"

// Dummy implementation for linking purposes, as the test doesn't rely on its full functionality.
void debug_cleanup(void) {}
void debug_init(const char *program_name, s_config *config) {}

int main() {
    const char *package = "wifidogx";
    const char *section = "common";
    const char *option = "test_option";
    const char *value1 = "initial_value";
    const char *value2 = "updated_value";
    char buffer[256];
    int ret;

    printf("--- Starting UCI function test ---\n");

    // Test 1: Set initial value
    printf("1. Testing uci_set_value (initial set)...\n");
    ret = uci_set_value(package, section, option, value1);
    if (ret != 0) {
        printf("   [FAIL] uci_set_value returned error code %d\n", ret);
        exit(1);
    }
    printf("   [SUCCESS] uci_set_value completed.\n\n");

    // Test 2: Get and verify initial value
    printf("2. Testing uci_get_value (verify initial set)...\n");
    memset(buffer, 0, sizeof(buffer));
    ret = uci_get_value(package, section, option, buffer, sizeof(buffer));
    if (ret != 0) {
        printf("   [FAIL] uci_get_value returned error code %d\n", ret);
        exit(1);
    }
    if (strcmp(buffer, value1) == 0) {
        printf("   [SUCCESS] Got correct value: '%s'\n\n", buffer);
    } else {
        printf("   [FAIL] Mismatch! Expected: '%s', Got: '%s'\n", value1, buffer);
        exit(1);
    }

    // Test 3: Set updated value
    printf("3. Testing uci_set_value (update)...\n");
    ret = uci_set_value(package, section, option, value2);
    if (ret != 0) {
        printf("   [FAIL] uci_set_value (update) returned error code %d\n", ret);
        exit(1);
    }
    printf("   [SUCCESS] uci_set_value (update) completed.\n\n");

    // Test 4: Get and verify updated value
    printf("4. Testing uci_get_value (verify update)...\n");
    memset(buffer, 0, sizeof(buffer));
    ret = uci_get_value(package, section, option, buffer, sizeof(buffer));
    if (ret != 0) {
        printf("   [FAIL] uci_get_value (update) returned error code %d\n", ret);
        exit(1);
    }
    if (strcmp(buffer, value2) == 0) {
        printf("   [SUCCESS] Got correct updated value: '%s'\n\n", buffer);
    } else {
        printf("   [FAIL] Mismatch! Expected: '%s', Got: '%s'\n", value2, buffer);
        exit(1);
    }

    // Test 5: Delete value
    printf("5. Testing uci_del_value...\n");
    ret = uci_del_value(package, section, option);
    if (ret != 0) {
        printf("   [FAIL] uci_del_value returned error code %d\n", ret);
        exit(1);
    }
    printf("   [SUCCESS] uci_del_value completed.\n\n");

    // Test 6: Verify deletion
    printf("6. Testing uci_get_value (verify deletion)...\n");
    ret = uci_get_value(package, section, option, buffer, sizeof(buffer));
    if (ret != 0) {
        printf("   [SUCCESS] uci_get_value correctly failed to find the deleted option.\n\n");
    } else {
        printf("   [FAIL] uci_get_value found a value ('%s') that should have been deleted.\n", buffer);
        // Clean up the stray option before exiting
        uci_del_value(package, section, option);
        exit(1);
    }

    printf("--- All UCI tests passed successfully! ---\n");
    return 0;
}