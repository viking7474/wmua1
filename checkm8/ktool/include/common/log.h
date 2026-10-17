#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32) || defined(WIN32)
#	include <windows.h>
#endif

#define MYJB_LOG_NAME "myjb_ktool.log"

#define RESET_COLOR   "\033[0m"
#define RED_COLOR     "\033[31m"
#define GREEN_COLOR   "\033[32m"
#define YELLOW_COLOR  "\033[33m"
#define BLUE_COLOR    "\033[34m"
#define MAGENTA_COLOR "\033[35m"
#define CYAN_COLOR    "\033[36m"
#define WHITE_COLOR   "\033[37m"
#define GRAY_COLOR    "\033[90m"

#define RAINBOW_COLORS \
    {RED_COLOR, GREEN_COLOR, YELLOW_COLOR, BLUE_COLOR, MAGENTA_COLOR, CYAN_COLOR}

// plain text log file written next to the exe (Windows) or in the working dir
static FILE *myjb_log_file;

static inline void
myjb_log_init(void) {
#if defined(_WIN32) || defined(WIN32)
	char path[MAX_PATH];
	DWORD n = GetModuleFileNameA(NULL, path, MAX_PATH);
	if(n > 0 && n < MAX_PATH) {
		char *slash = strrchr(path, '\\');
		if(slash != NULL && (strlen(path) + strlen(MYJB_LOG_NAME)) < MAX_PATH) {
			slash[1] = '\0';
			strcat(path, MYJB_LOG_NAME);
			myjb_log_file = fopen(path, "w");
		}
	}
#endif
	if(myjb_log_file == NULL) {
		myjb_log_file = fopen(MYJB_LOG_NAME, "w");
	}
	if(myjb_log_file != NULL) {
		fprintf(myjb_log_file, "== myjb checkm8 tool log ==\n");
		fflush(myjb_log_file);
	}
}

static inline void
myjb_log_exit(int code) {
	if(myjb_log_file != NULL) {
		fprintf(myjb_log_file, "[EXIT] process exit code %d\n", code);
		fflush(myjb_log_file);
	}
}

static inline void
myjb_log(const char *color, const char *label, const char *file, int line, const char *fmt, ...) {
	va_list ap, ap2;
	char tsbuf[16] = "--:--:--";
	time_t now = time(NULL);
	struct tm *tm_now = localtime(&now);

	if(tm_now != NULL) {
		strftime(tsbuf, sizeof(tsbuf), "%H:%M:%S", tm_now);
	}

	va_start(ap, fmt);
	va_copy(ap2, ap);
	printf(GRAY_COLOR "[%s] " "%s%s (%s:%d)" GRAY_COLOR " --> " WHITE_COLOR, tsbuf, color, label, file, line);
	vprintf(fmt, ap);
	printf(RESET_COLOR "\n");
	fflush(stdout);
	va_end(ap);

	if(myjb_log_file != NULL) {
		fprintf(myjb_log_file, "[%s] %s (%s:%d) --> ", tsbuf, label, file, line);
		vfprintf(myjb_log_file, fmt, ap2);
		fputc('\n', myjb_log_file);
		fflush(myjb_log_file);
	}
	va_end(ap2);
}

// style: [INFO] (filename:line) --> message
#define LOG_INFO(fmt, ...) \
	myjb_log(WHITE_COLOR, "[INFO]", __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) \
	myjb_log(YELLOW_COLOR, "[WARN]", __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...) \
	myjb_log(RED_COLOR, "[ERROR]", __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_DEBUG(fmt, ...) \
	myjb_log(CYAN_COLOR, "[DEBUG]", __FILE__, __LINE__, fmt, ##__VA_ARGS__)

// log_rainbow: just print out the message with every character a different color
#define LOG_RAINBOW(fmt, ...) do { \
	const char *colors[] = RAINBOW_COLORS; \
	int n = sizeof(colors) / sizeof(colors[0]); \
	for (int i = 0; fmt[i]; ++i) { \
		printf("%s%c", colors[i % n], fmt[i]); \
	} \
	printf(RESET_COLOR "\n"); \
	fflush(stdout); \
	if(myjb_log_file != NULL) { \
		fprintf(myjb_log_file, fmt "\n", ##__VA_ARGS__); \
		fflush(myjb_log_file); \
	} \
} while (0)

#endif  // LOG_H
