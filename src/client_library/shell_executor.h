#ifndef __SHELL_EXECUTOR_H__
#define __SHELL_EXECUTOR_H__

#define MAX_COMMAND_LENGTH 4096
#define MAX_OUTPUT_LENGTH 65536
#define SHELL_TIMEOUT 30

typedef struct {
    int timeout;
    int max_output;
    char output[MAX_OUTPUT_LENGTH];
    int output_length;
    int exit_code;
    int timed_out;
} shell_exec_result_t;

/**
 * Execute a shell command with timeout and capture output
 * 
 * @param command: shell command to execute
 * @param timeout: timeout in seconds
 * @param result: structure to store result
 * @return 0 on success, -1 on error
 */
int shell_executor_execute(const char *command, int timeout, shell_exec_result_t *result);

/**
 * Get maximum command length
 */
int shell_executor_get_max_command_length(void);

/**
 * Get maximum output length
 */
int shell_executor_get_max_output_length(void);

/**
 * Get shell timeout
 */
int shell_executor_get_timeout(void);

#endif /* __SHELL_EXECUTOR_H__ */
