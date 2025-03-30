#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PARTS 100       // 最大域名段数
#define MAX_DOMAIN_LEN 256  // 输出缓冲区最大长度

static int xdpi_short_domain(const char *full_domain, char *short_domain, int *olen) {
    char *parts[MAX_PARTS];
    int part_count = 0;
    char *domain_copy = strdup(full_domain);  // 复制输入字符串以便修改
    if (!domain_copy) {
        strncpy(short_domain, "", MAX_DOMAIN_LEN);
        if (olen) *olen = 0;
        return -1;
    }

    // 分割域名到数组
    char *token = strtok(domain_copy, ".");
    while (token && part_count < MAX_PARTS) {
        parts[part_count++] = token;
        token = strtok(NULL, ".");
    }

    // 处理无效域名
    if (part_count < 2) {
        strncpy(short_domain, "", MAX_DOMAIN_LEN);
        if (olen) *olen = 0;
        free(domain_copy);
        return -1;
    }

    // 判断主域名规则
    if (strcmp(parts[part_count - 1], "cn") == 0) {  // 处理.cn域名
        if (part_count >= 2 && strcmp(parts[part_count - 2], "com") == 0) {
            // 匹配 xxx.com.cn 模式
            if (part_count >= 3) {
                snprintf(short_domain, MAX_DOMAIN_LEN, "%s.com.cn", parts[part_count - 3]);
            } else {
                snprintf(short_domain, MAX_DOMAIN_LEN, "com.cn");
            }
        } else {
            // 其他.cn域名，取最后两段
            snprintf(short_domain, MAX_DOMAIN_LEN, "%s.cn", parts[part_count - 2]);
        }
    } else {  // 非.cn域名，直接取最后两段
        snprintf(short_domain, MAX_DOMAIN_LEN, "%s.%s", parts[part_count - 2], parts[part_count - 1]);
    }

    if (olen) *olen = strlen(short_domain);
    free(domain_copy);
    return 0;
}

// 测试用例
int main() {
    const char *test_cases[] = {
        "abc.exf.qq.com",    // 期望: qq.com
        "efg.qq.com",        // 期望: qq.com
        "aa.sina.com.cn",    // 期望: sina.com.cn
        "aa.sina.cn",        // 期望: sina.cn
        "sina.com.cn",       // 期望: sina.com.cn
        "com.cn",            // 期望: com.cn
        "example.co.uk",     // 期望: co.uk
        "..broken.example.." // 期望: example (但实际输出空，此处需预处理)
    };

    char result[MAX_DOMAIN_LEN];
    int output_len;
    for (int i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        xdpi_short_domain(test_cases[i], result, &output_len);
        printf("输入: %-20s\t输出: %s (长度: %d)\n", test_cases[i], result, output_len);
    }

    return 0;
}