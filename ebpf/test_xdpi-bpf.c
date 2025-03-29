#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Mock function to replicate the behavior of bpf_strstr kernel function
int test_strstr(const char *str, unsigned int str_sz, const char *substr, unsigned int substr_sz)
{
    if (substr_sz == 0)
    {
        return 0;
    }
    if (substr_sz > str_sz)
    {
        return -1;
    }
    for (size_t i = 0; i <= str_sz - substr_sz; i++)
    {
        size_t j = 0;
        while (j < substr_sz && str[i + j] == substr[j])
        {
            j++;
        }
        if (j == substr_sz)
        {
            return i;
        }
    }
    return -1;
}

void run_test(const char *str, const char *substr, int expected_result, const char *test_name)
{
    int result = test_strstr(str, strlen(str), substr, strlen(substr));
    if (result == expected_result) {
        printf("✓ Test passed: %s\n", test_name);
    } else {
        printf("✗ Test failed: %s\n", test_name);
        printf("  Expected: %d, Got: %d\n", expected_result, result);
    }
}

int main()
{
    printf("Running tests for bpf_strstr function:\n");

    // Basic tests
    run_test("Hello, World!", "World", 7, "Basic matching");
    run_test("Hello, World!", "Hello", 0, "Match at beginning");
    run_test("Hello, World!", "!", 12, "Match at end");
    run_test("Hello, World!", "", 0, "Empty substring");
    
    // Negative tests
    run_test("Hello, World!", "Goodbye", -1, "No match");
    run_test("Hello, World!", "WORLD", -1, "Case sensitivity");
    run_test("Hello", "Hello, World!", -1, "Substring longer than string");
    
    // Edge cases
    run_test("", "", 0, "Empty string and empty substring");
    run_test("", "test", -1, "Empty string, non-empty substring");
    run_test("aaaaa", "aa", 0, "Multiple possible matches, returns first");
    
    // HTTP protocol related tests (simulating DPI use case)
    run_test("GET /index.html HTTP/1.1", "GET", 0, "HTTP GET method");
    run_test("Host: example.com", "Host:", 0, "HTTP Host header");
    run_test("Content-Type: application/json", "application/json", 14, "Content type");
    
    // Special characters
    run_test("Test\nstring", "\n", 4, "Newline character");
    run_test("Path/to/file", "/", 4, "Forward slash");
    run_test("C:\\Windows\\System32", "\\", 1, "Backslash");
    
    return 0;
}