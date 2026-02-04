#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <errno.h>
#include <syslog.h>
#include "shell_executor.h"


static pid_t child_pid = -1;

/**
 * Signal handler for timeout
 */
static void timeout_handler(int sig) {
    if (child_pid > 0) {
        kill(child_pid, SIGKILL);
    }
}

/**
 * Execute a shell command with timeout and capture output
 * 
 * @param command: shell command to execute
 * @param timeout: timeout in seconds
 * @param result: structure to store result
 * @return 0 on success, -1 on error
 */
int shell_executor_execute(const char *command, int timeout, shell_exec_result_t *result) {
    if (!command || !result) {
        syslog(LOG_ERR, "[shell_executor] Invalid parameters");
        return -1;
    }

    // Validate command length
    if (strlen(command) > MAX_COMMAND_LENGTH) {
        syslog(LOG_ERR, "[shell_executor] Command too long");
        snprintf(result->output, MAX_OUTPUT_LENGTH, "Error: Command too long (max %d bytes)", MAX_COMMAND_LENGTH);
        result->output_length = strlen(result->output);
        return -1;
    }

    // Sanitize timeout
    if (timeout <= 0 || timeout > SHELL_TIMEOUT) {
        timeout = SHELL_TIMEOUT;
    }

    result->timed_out = 0;
    result->exit_code = -1;
    result->output_length = 0;
    memset(result->output, 0, MAX_OUTPUT_LENGTH);

    // Create pipe for capturing output
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        syslog(LOG_ERR, "[shell_executor] pipe() failed: %s", strerror(errno));
        snprintf(result->output, MAX_OUTPUT_LENGTH, "Error: Failed to create pipe");
        result->output_length = strlen(result->output);
        return -1;
    }

    // Fork child process
    child_pid = fork();
    if (child_pid == -1) {
        syslog(LOG_ERR, "[shell_executor] fork() failed: %s", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        snprintf(result->output, MAX_OUTPUT_LENGTH, "Error: Failed to fork process");
        result->output_length = strlen(result->output);
        return -1;
    }

    if (child_pid == 0) {
        // Child process: execute command
        close(pipefd[0]); // Close read end
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        // Execute shell command
        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        exit(127); // exec failed
    }

    // Parent process: read output and wait for child
    close(pipefd[1]); // Close write end

    // Set up timeout handler
    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = timeout_handler;
    sigaction(SIGALRM, &sa, &old_sa);
    alarm(timeout);

    // Read output from child
    int bytes_read = 0;
    char buffer[4096];
    while (bytes_read < MAX_OUTPUT_LENGTH - 1) {
        ssize_t n = read(pipefd[0], buffer, sizeof(buffer) - 1);
        if (n <= 0) {
            break;
        }
        
        int remaining = MAX_OUTPUT_LENGTH - 1 - bytes_read;
        int to_copy = (n < remaining) ? n : remaining;
        memcpy(result->output + bytes_read, buffer, to_copy);
        bytes_read += to_copy;
    }
    result->output[bytes_read] = '\0';
    result->output_length = bytes_read;

    close(pipefd[0]);

    // Wait for child process
    int status;
    pid_t waited = waitpid(child_pid, &status, 0);
    child_pid = -1;

    // Cancel alarm
    alarm(0);
    sigaction(SIGALRM, &old_sa, NULL);

    if (waited == -1) {
        if (errno == EINTR) {
            // Timeout occurred
            result->timed_out = 1;
            result->exit_code = -1;
            syslog(LOG_WARNING, "[shell_executor] Command timed out after %d seconds", timeout);
            return -1;
        }
        syslog(LOG_ERR, "[shell_executor] waitpid() failed: %s", strerror(errno));
        return -1;
    }

    // Extract exit code
    if (WIFEXITED(status)) {
        result->exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result->exit_code = 128 + WTERMSIG(status);
    } else {
        result->exit_code = -1;
    }

    syslog(LOG_DEBUG, "[shell_executor] Command executed: exit_code=%d, output_length=%d", 
           result->exit_code, result->output_length);

    return 0;
}

/**
 * Get maximum command length
 */
int shell_executor_get_max_command_length(void) {
    return MAX_COMMAND_LENGTH;
}

/**
 * Get maximum output length
 */
int shell_executor_get_max_output_length(void) {
    return MAX_OUTPUT_LENGTH;
}

/**
 * Get shell timeout
 */
int shell_executor_get_timeout(void) {
    return SHELL_TIMEOUT;
}
