#ifndef jbutil_install_h
#define jbutil_install_h

#include "common.h"

#define APT_BIGBOSS_REPO "Types: deb\nURIs: http://apt.thebigboss.org/repofiles/cydia/\nSuites: stable\nComponents: main\n\n"
#define APT_HAVOC_REPO "Types: deb\nURIs: https://havoc.app/\nSuites: ./\nComponents:\n\n"
#define APT_CHARIZ_REPO "Types: deb\nURIs: https://repo.chariz.com/\nSuites: ./\nComponents:\n\n"
#define APT_PACKIX_REPO "Types: deb\nURIs: https://repo.packix.com/\nSuites: ./\nComponents:\n\n"
#define APT_AMETHYST_REPO "Types: deb\nURIs: https://repo.amethystjb.com/\nSuites: ./\nComponents:\n\n"
#define APT_SONAR_REPO "Types: deb\nURIs: https://repo.libsonar.com/\nSuites: ./\nComponents:\n\n"

#define ZEBRA_BIGBOSS_REPO "deb http://apt.thebigboss.org/repofiles/cydia/ stable main\n"
#define ZEBRA_HAVOC_REPO "deb https://havoc.app/ ./\n"
#define ZEBRA_CHARIZ_REPO "deb https://repo.chariz.com/ ./\n"
#define ZEBRA_PACKIX_REPO "deb https://repo.packix.com/ ./\n"
#define ZEBRA_PROCURSUS_1500_REPO "deb https://apt.procurs.us/ iphoneos-arm64/1500 main\n"
#define ZEBRA_PROCURSUS_1600_REPO "deb https://apt.procurs.us/ iphoneos-arm64/1600 main\n"
#define ZEBRA_AMETHYST_REPO "deb https://repo.amethystjb.com/ ./\n"
#define ZEBRA_SONAR_REPO "deb https://repo.libsonar.com/ ./\n"

#define AMETHYST_SOURCES_FILE "/etc/apt/sources.list.d/amethyst.sources"
#define SILEO_SOURCES_FILE "/etc/apt/sources.list.d/sileo.sources"
#define ZEBRA_SOURCES_FILE "/var/mobile/Library/Application Support/xyz.willy.Zebra/sources.list"
#define ZEBRA_APP_SUPPORT "/var/mobile/Library/Application Support/xyz.willy.Zebra"

int install_deb(char *deb_path);
int configure_repos(void);
int install_bootstrap(const char *tar_path);

#endif /* jbutil_install_h */
