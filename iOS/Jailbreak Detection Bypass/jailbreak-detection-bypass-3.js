// Run: frida -U -f com.blah.Blah -l bypass.js --no-pause


// This is https://gist.github.com/izadgot/5783334b11563fb08fee4cd250455edea combination of the following:
// - https://gist.github.com/izadgot/5783334b11563fb08fee4cd250455ede
// - https://codeshare.frida.re/@liangxiaoyi1024/ios-jailbreak-detection-bypass/

// These together worked again current client starting with TR, but only after
// I identified the /private/var/lib/apt was missing from the second script and added it
// interesting, it was included in the first script, but the fileExistsAtPath and fopen
// hooks didn't handle it...
//
// The issue was that it was receiving a var of "/private/var/lib/apt/", but had
// "/private/var/lib/apt/" in the list. So I don't think we really need the low level
// stat/stat64, but we could use only those since all higher functions should rely on them.


// private/var/lib/apt

// - get list of classes to see if there is one for jailbreak detection we can directly override
// - dump the list of paths, excluding ones that would not be used for JB detection
// - In general, we want two things from this script:
//   1. A solid base for bypassic jb detection
//   2. informative debugging to help us find what we've missed

const jailbreakPaths = [
    "/Applications/Cydia.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSetttings.app",
    "/Applications/WinterBoard.app",
    "/Applications/blackra1n.app",
    "/Applications/Terminal.app",
    "/Applications/Pirni.app",
    "/Applications/iFile.app",
    "/Applications/iProtect.app",
    "/Applications/Backgrounder.app",
    "/Applications/biteSMS.app",
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/Library/MobileSubstrate/DynamicLibraries/SBSettings.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/SBSettings.plist",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/System/Library/LaunchDaemons/com.bigboss.sbsettingsd.plist",
    "/System/Library/PreferenceBundles/CydiaSettings.bundle",
    "/bin/bash",
    "/bin/sh",
    "/etc/apt",
    "/etc/ssh/sshd_config",
    "/etc/profile.d/terminal.sh",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/private/var/lib/apt",
    "/private/var/root/Media/Cydia",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/SBSettings/Themes",
    "/private/var/lib/dpkg/info/cydia-sources.list",
    "/private/var/lib/dpkg/info/cydia.list",
    "/private/etc/profile.d/terminal.sh",
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/substrate",
    "/usr/lib/libhooker.dylib",
    "/usr/bin/cycript",
    "/usr/bin/ssh",
    "/usr/bin/sshd",
    "/usr/sbin/sshd",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/usr/libexec/cydia",
    "/usr/sbin/sshd",
    "/var/cache/apt",
    "/var/lib/cydia",
    "/var/log/syslog",
    "/var/tmp/cydia.log",
    "/var/lib/dpkg/info/cydia-sources.list",
    "/var/lib/dpkg/info/cydia.list",
    "/var/lib/dpkg/info/mobileterminal.list",
    "/var/lib/dpkg/info/mobileterminal.postinst",
    "/User/Library/SBSettings",
    "/usr/bin/sbsettingsd",
    "/var/mobile/Library/SBSettings"
];

//App URL list in lower case for canOpenURL
const canOpenURL = [
    "cydia"
]

if (ObjC.available) {
    var paths = [
        "/Applications/blackra1n.app",
        "/Applications/Cydia.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/SBSetttings.app",
        "/Applications/WinterBoard.app",
        "/bin/bash",
        "/bin/sh",
        "/bin/su",
        "/etc/apt",
        "/etc/ssh/sshd_config",
        "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/pguntether",
        "/private/var/lib/cydia",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/private/var/stash",
        "/private/var/tmp/cydia.log",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        "/usr/bin/cycript",
        "/usr/bin/ssh",
        "/usr/bin/sshd",
        "/usr/libexec/sftp-server",
        "/usr/libexec/ssh-keysign",
        "/usr/sbin/frida-server",
        "/usr/sbin/sshd",
        "/var/cache/apt",
        "/var/lib/cydia",
        "/var/log/syslog",
        "/var/mobile/Media/.evasi0n7_installed",
        "/var/tmp/cydia.log",
        "/private/var/lib/apt", // mine

    ];
    var f = Module.findExportByName("libSystem.B.dylib", "stat64");
    Interceptor.attach(f, {
        onEnter: function(args) {
            this.is_common_path = false;
            var arg = Memory.readUtf8String(args[0]);
            // console.log("stat64 arg:", arg)
            for (var path in paths) {
                if (arg.indexOf(paths[path]) > -1) {
                    // console.log("Hooking native function stat64: " + arg);
                    this.is_common_path = true;
                    //return -1;
                }
            }
        },
        onLeave: function(retval) {
            if (this.is_common_path) {
                // console.log("stat64 Bypass!!!");
                retval.replace(-1);
            }
        }
    });
    var f = Module.findExportByName("libSystem.B.dylib", "stat");
    Interceptor.attach(f, {
        onEnter: function(args) {
            this.is_common_path = false;
            var arg = Memory.readUtf8String(args[0]);
            for (var path in paths) {
                if (arg.indexOf(paths[path]) > -1) {
                    // console.log("Hooking native function stat: " + arg);
                    this.is_common_path = true;
                    //return -1;
                }
            }
        },
        onLeave: function(retval) {
            if (this.is_common_path) {
                // console.log("stat Bypass!!!");
                retval.replace(-1);
            }
        }
    });

    try {
        //Hooking fileExistsAtPath:
        Interceptor.attach(ObjC.classes.NSFileManager["- fileExistsAtPath:"].implementation, {
            onEnter(args) {
                // Use a marker to check onExit if we need to manipulate
                // the response.
                this.is_common_path = false;
                // Extract the path
                this.path = new ObjC.Object(args[2]).toString();
                console.log("fileExistsAtPath:", this.path)
                // check if the looked up path is in the list of common_paths
                if (jailbreakPaths.indexOf(this.path) >= 0) {
                    // Mark this path as one that should have its response
                    // modified if needed.
                    console.log("MARKING")
                    this.is_common_path = true;
                }
            },
            onLeave(retval) {
                // stop if we dont care about the path
                if (!this.is_common_path) {
                    return;
                }

                // ignore failed lookups
                if (retval.isNull()) {
                    // console.log(`fileExistsAtPath: try to check for ` + this.path + ' was failed');
                    return;
                }
                // console.log(`fileExistsAtPath: check for ` + this.path + ` was successful with: ` + retval.toString() + `, marking it as failed.`);
                retval.replace(new NativePointer(0x00));
            },
        });

        //Hooking fopen
        Interceptor.attach(Module.findExportByName(null, "fopen"), {
            onEnter(args) {
                this.is_common_path = false;
                // Extract the path
                this.path = args[0].readCString();
                console.log("fopen:", this.path);
                // check if the looked up path is in the list of common_paths
                if (jailbreakPaths.indexOf(this.path) >= 0) {
                    // Mark this path as one that should have its response
                    // modified if needed.
                    this.is_common_path = true;
                }
            },
            onLeave(retval) {
                // stop if we dont care about the path
                if (!this.is_common_path) {
                    return;
                }

                // ignore failed lookups
                if (retval.isNull()) {
                    // console.log(`fopen: try to check for ` + this.path + ' was failed');
                    return;
                }
                // console.log(`fopen: check for ` + this.path + ` was successful with: ` + retval.toString() + `, marking it as failed.`);
                retval.replace(new NativePointer(0x00));
            },
        });

        //Hooking canOpenURL for Cydia
        Interceptor.attach(ObjC.classes.UIApplication["- canOpenURL:"].implementation, {
            onEnter(args) {
                this.is_flagged = false;
                // Extract the path
                this.path = new ObjC.Object(args[2]).toString();
                let app = this.path.split(":")[0].toLowerCase();
                if (canOpenURL.indexOf(app) >= 0) {
                    this.is_flagged = true;
                }
            },
            onLeave(retval) {
                if (!this.is_flagged) {
                    return;
                }

                // ignore failed
                if (retval.isNull()) {
                    return;
                }
                // console.log(`canOpenURL: check for ` +
                    // this.path + ` was successful with: ` +
                    // retval.toString() + `, marking it as failed.`);
                retval.replace(new NativePointer(0x00));
            }
        });

        //Hooking libSystemBFork
        const libSystemBdylibFork = Module.findExportByName("libSystem.B.dylib", "fork");
        if (libSystemBdylibFork) {
            Interceptor.attach(libSystemBdylibFork, {
                onLeave(retval) {
                    // already failed forks are ok
                    if (retval.isNull()) {
                        return;
                    }
                    // console.log(`Call to libSystem.B.dylib::fork() was successful with ` +
                    // retval.toString() + ` marking it as failed.`);
                    retval.replace(new NativePointer(0x0));
                },
            });
        }
    }
    catch (err) {
        // console.log("Exception : " + err.message);
    }
}