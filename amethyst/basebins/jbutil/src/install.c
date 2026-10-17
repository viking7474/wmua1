#include "util.h"
#include "extract.h"
#include "install.h"

int configure_apt_repos(void) {
    FILE *sources = fopen(SILEO_SOURCES_FILE, "wb+");
    if (sources != NULL) {
        fprintf(sources, APT_BIGBOSS_REPO);
        fprintf(sources, APT_HAVOC_REPO);
        fprintf(sources, APT_CHARIZ_REPO);
        fprintf(sources, APT_PACKIX_REPO);
        fflush(sources);
        fclose(sources);

        chmod(SILEO_SOURCES_FILE, 0644);
        chown(SILEO_SOURCES_FILE, 0, 0);
        sync();
    }

    sources = fopen(AMETHYST_SOURCES_FILE, "wb+");
    if (sources != NULL) {
        fprintf(sources, APT_AMETHYST_REPO);
        fprintf(sources, APT_SONAR_REPO);
        fflush(sources);
        fclose(sources);

        chmod(AMETHYST_SOURCES_FILE, 0644);
        chown(AMETHYST_SOURCES_FILE, 0, 0);
        sync();
    }
    return 0;
}

int configure_zebra_repos(void) {
    if (access(ZEBRA_APP_SUPPORT, F_OK) != 0) {
        mkdir(ZEBRA_APP_SUPPORT, 0777);
        chown(ZEBRA_APP_SUPPORT, 501, 501);
        sync();
    }
    
    FILE *sources = fopen(ZEBRA_SOURCES_FILE, "wb+");
    if (sources == NULL) return -1;

    CFDictionaryRef sys_ver = _CFCopySystemVersionDictionary();
    CFStringRef str = (CFStringRef)CFDictionaryGetValue(sys_ver, CFSTR("ProductVersion"));
    uint16_t version[3] = {0};
    char buf[128] = {0};

    CFStringGetCString(str, buf, sizeof(buf)-1, kCFStringEncodingUTF8);    
    sscanf(buf, "%hu.%hu.%hu", &version[0], &version[1], &version[2]);
    CFRelease(sys_ver);

    if (version[0] == 13) {
        fprintf(sources, ZEBRA_PROCURSUS_1600_REPO);
    } else {
        fprintf(sources, ZEBRA_PROCURSUS_1500_REPO);
    }

    fprintf(sources, ZEBRA_BIGBOSS_REPO);
    fprintf(sources, ZEBRA_HAVOC_REPO);
    fprintf(sources, ZEBRA_CHARIZ_REPO);
    fprintf(sources, ZEBRA_PACKIX_REPO);
    fprintf(sources, ZEBRA_AMETHYST_REPO);
    fprintf(sources, ZEBRA_SONAR_REPO);
    fflush(sources);
    fclose(sources);

    chmod(ZEBRA_SOURCES_FILE, 0644);
    chown(ZEBRA_SOURCES_FILE, 0, 0);
    sync();
    return 0;
}

int install_deb(char *deb_path) {
    char *args[] = {"dpkg", "--force-all", "-i", deb_path, NULL};
    int status = run_command("/usr/bin/dpkg", args);
    if (status != 0) return status;

    if (strstr(deb_path, "sileo") || strstr(deb_path, "zebra")) {
        if (configure_apt_repos() != 0) return -1;
        if (strstr(deb_path, "zebra")) {
            return configure_zebra_repos();
        }
    }
    return status;
}

int prep_bootstrap(void) {
    char *args[] = {"zsh", "/prep_bootstrap.sh", NULL};
    char *env[] = {
        "PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/lib:/usr/local/lib:/lib:/usr/libexec:/usr/lib/bash",
        "JBUTIL_SPAWN=1",
        NULL
    };

    pid_t pid = -1;
    int status = 0;
    int err = posix_spawn(&pid, "/usr/bin/zsh", NULL, NULL, args, env);
    if (err != 0 || pid == -1) return -1;
    
    do { if (waitpid(pid, &status, 0) == -1) return -1; }
    while (!WIFEXITED(status) && !WIFSIGNALED(status));
    return status;
}


int install_bootstrap(const char *tar_path) {
    if (extract_lzfse_tar(tar_path, "/") != 0) return -1;
    prep_bootstrap();

    FILE *file = fopen("/.installed_amethyst", "wb+");
    if (file != NULL) {
        fclose(file);
        chmod("/.installed_amethyst", 0644);
        chown("/.installed_amethyst", 0, 0);
    }

    file = fopen("/.procursus_strapped", "wb+");
    if (file != NULL) {
        fclose(file);
        chmod("/.procursus_strapped", 0644);
        chown("/.procursus_strapped", 0, 0);
    }

    unlink("/prep_bootstrap.sh");
    sync();
    return 0;
}
